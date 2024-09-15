import {
    getPublicKeyAsync,
    verifyAsync,
    signAsync,
    utils,
} from '@noble/ed25519'
// import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
// import { sha512 } from '@noble/hashes/sha512'
import { xchacha20poly1305 } from '@noble/ciphers/chacha'
import { x25519 } from '@noble/curves/ed25519'
import { randomBytes } from '@noble/ciphers/webcrypto'
import * as u from 'uint8arrays'
import { BASE58_DID_PREFIX } from '../constants.js'
import { toString, fromString, generateEntropy } from '../util'
import { magicBytes, parseMagicBytes } from '../index.js'
import type { DID } from '../types'

export type Keypair = {
    publicKey:Uint8Array;
    privateKey:Uint8Array;
}

/**
 * Generate a secret key, possibly using an existing key buffer.
 */
export function x25519Keygen (
    seed:Uint8Array|string = generateEntropy()
):Keypair {
    const sk = sha256(seed)
    const pk = x25519.scalarMultBase(sk)
    return { privateKey: sk, publicKey: pk }
}

/**
 * Create a new `ed25519` keypair (for signatures).
 */
export async function create ():Promise<Keypair> {
    const privKey = utils.randomPrivateKey()  // Secure random key
    const pubKey = await getPublicKeyAsync(privKey)  // Sync methods below

    return { publicKey: pubKey, privateKey: privKey }
}

/**
 * Get a shared secret key.
 *
 * Async so that it matches the webcrypto API.
 */
export async function getSharedKey (
    privateKey:Uint8Array,
    publicKey:Uint8Array
):Promise<Uint8Array> {
    const key = x25519.getSharedSecret(privateKey, publicKey)
    return key
}

/**
 * Return the given public key as a `base64pad` encoded string.
 */
export function exportPublicKey (keys:Keypair):string {
    return toString(keys.publicKey)
}

export async function sign (
    msg:string|Uint8Array,
    privKey:Uint8Array,
    { format }:{ format:'raw' },
):Promise<Uint8Array>

export async function sign (
    msg:string|Uint8Array,
    privKey:Uint8Array,
    { format }:{ format:'string' },
):Promise<string>

export async function sign (
    msg:string|Uint8Array,
    privKey:Uint8Array,
):Promise<string>

/**
 * Sign the given message. Return the signature as a string by default,
 * or pass `{ format: 'raw' }` to return a `Uint8Array`.
 */
export async function sign (
    msg:string|Uint8Array,
    privKey:Uint8Array,
    { format }:{ format: 'string'|'raw' } = { format: 'string' },
):Promise<Uint8Array|string> {
    const msgData:Uint8Array = (typeof msg === 'string' ?
        u.fromString(msg) :
        msg)

    const sig = await signAsync(msgData, privKey)

    if (format === 'string') {
        return toString(sig)
    }

    return sig
}

/**
 * Verify the given signature and public key.
 * Returns `true` iff valid.
 */
export async function verify (
    msg:string|Uint8Array,
    sig:string|Uint8Array,
    publicKey:Uint8Array|DID,
):Promise<boolean> {
    const pubBuf = (typeof publicKey === 'string' ?  // <-- DID format
        (didToPublicKey(publicKey)).publicKey :
        publicKey)

    console.log('sig', sig)
    console.log('msg', msg)

    const sigBuf = typeof sig === 'string' ? fromString(sig) : sig
    const msgBuf = typeof msg === 'string' ? u.fromString(msg) : msg

    console.log('**veryinfying**', sigBuf, msgBuf)

    try {
        return (await verifyAsync(sigBuf, msgBuf, pubBuf))
    } catch (_err) {
        console.log('errrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr', _err)
        return false
    }
}

export function didToPublicKey (did:string):({
    publicKey:Uint8Array,
    type:'ed25519'
}) {
    if (!did.startsWith(BASE58_DID_PREFIX)) {
        throw new Error(
            'Please use a base58-encoded DID formatted `did:key:z...`')
    }

    const didWithoutPrefix = ('' + did.substring(BASE58_DID_PREFIX.length))
    const magicalBuf = u.fromString(didWithoutPrefix, 'base58btc')
    const { keyBuffer } = parseMagicBytes(magicalBuf.buffer)

    return {
        publicKey: new Uint8Array(keyBuffer),
        type: 'ed25519'
    }
}

/**
 * Return the public key encoded as a DID.
 */
export function publicKeyToDid (
    keys:Keypair,
):DID {
    const pubKey = keys.publicKey
    const prefix = magicBytes.ed25519
    const prefixedBuf = u.concat([prefix, pubKey])
    return (
        BASE58_DID_PREFIX +
        u.toString(prefixedBuf, 'base58btc')
    ) as DID
}

export async function encrypt (
    msg:string|Uint8Array,
    privateKey:Uint8Array,
    publicKey:Uint8Array|string
):Promise<string>

export async function encrypt (
    msg:string|Uint8Array,
    privateKey:Uint8Array,
    publicKey:Uint8Array|string,
    opts:{ format:'raw'|'string' } = { format: 'string' }
):Promise<Uint8Array|string> {
    const pubKeyBuf = (typeof publicKey === 'string' ?
        fromString(publicKey) :
        publicKey)
    const sharedSecret = await getSharedKey(privateKey, pubKeyBuf)
    const nonce = randomBytes(24)
    const chacha = xchacha20poly1305(sharedSecret, nonce)
    const msgBuf = typeof msg === 'string' ? u.fromString(msg) : msg
    const encrypted = chacha.encrypt(msgBuf)
    console.log('**encrypted**', encrypted)
    if (opts.format === 'string') {
        return toString(new Uint8Array([...nonce, ...encrypted]))
    }

    return new Uint8Array([...nonce, ...encrypted])
}

export async function decrypt (
    encryptedData:string|Uint8Array,
    privateKey:Uint8Array,
    publicKey:Uint8Array|string,  // Uint8Array or base64
):Promise<string>

export async function decrypt (
    encryptedData:string|Uint8Array,
    privateKey:Uint8Array,
    publicKey:Uint8Array|string,  // Uint8Array or base64
    opts:{ format:'raw'| 'string'} = { format: 'string' }
) {
    const pubKey = (typeof publicKey === 'string' ?
        fromString(publicKey) :
        publicKey)

    const msgBuf = (typeof encryptedData === 'string' ?
        fromString(encryptedData) :
        encryptedData)

    console.log('**msg buf**', msgBuf)

    const sharedSecret = await getSharedKey(privateKey, pubKey)

    console.log('**secret**', sharedSecret)

    // const sharedSecret = hkdf(
    //     sha256,
    //     x25519.getSharedSecret(privateKey, pubKey),
    //     randomBytes(24),
    //     'example',
    //     24
    // )

    // const sharedSecret = hkdf(sha256, privateKey, pubKey, 'example', 24)
    const nonce = msgBuf.slice(0, 24)
    const cipher = xchacha20poly1305(sharedSecret, nonce)
    const cipherBytes = msgBuf.slice(24)  // slice -- 24 -> end
    const decrypted = cipher.decrypt(cipherBytes)

    return opts.format === 'string' ? u.toString(decrypted) : decrypted
}
