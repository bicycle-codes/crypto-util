import {
    getPublicKeyAsync,
    verifyAsync,
    signAsync,
    utils,
} from '@noble/ed25519'
import { hkdf } from '@noble/hashes/hkdf'
import { x25519 } from '@noble/curves/ed25519'
import * as u from 'uint8arrays'
import { BASE58_DID_PREFIX } from '../constants.js'
import { toString, fromString } from '../util'
import { magicBytes, parseMagicBytes } from '../index.js'
import type { DID, Msg } from '../types'

export type Keypair = {
    publicKey:Uint8Array;
    privateKey:Uint8Array;
}

/**
 * Create a new keypair.
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
    const msgData:Uint8Array = typeof msg === 'string' ?
        u.fromString(msg) :
        msg

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
    const pubBuf = (typeof publicKey === 'string' ?
        (didToPublicKey(publicKey)).publicKey :
        publicKey)

    const sigBuf = typeof sig === 'string' ? fromString(sig) : sig
    const msgBuf = typeof msg === 'string' ? u.fromString(msg) : msg

    try {
        return (await verifyAsync(sigBuf, msgBuf, pubBuf))
    } catch (_err) {
        console.log('errrrrrr', _err)
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
    msg:Msg,
    privKey:Uint8Array,
    pubKey:Uint8Array|string,
    opts:{ format:'raw'|'string' } = { format: 'string' }
):Promise<Uint8Array|string> {
    const pubKeyBuf = typeof pubKey === 'string' ? fromString(pubKey) : pubKey
    const sharedSecret = await getSharedKey(privKey, pubKeyBuf)
}

// /**
//  * Encrypt the given message. Returns a string by default. Pass
//  * `{ format: 'raw' }` to return a `Uint8Array`.
//  */
// export async function encrypt (
//     msg:Msg,
//     privateKey:PrivateKey,
//     publicKey:string|PublicKey,  // <-- base64 or key
//     { format }:{ format: 'base64'|'raw' } = { format: 'base64' },
//     charSize:CharSize = DEFAULT_CHAR_SIZE,
//     curve:EccCurve = DEFAULT_ECC_CURVE,
//     opts?:Partial<{
//         alg:SymmAlg
//         length:SymmKeyLength
//         iv:ArrayBuffer
//     }>
// ):Promise<Uint8Array|string> {
//     const importedPublicKey = (typeof publicKey === 'string' ?
//         await importPublicKey(publicKey, curve, KeyUse.Encrypt) :
//         publicKey)

//     const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
//     const encrypted = await aes.encryptBytes(
//         normalizeUnicodeToBuf(msg, charSize),
//         cipherKey,
//         opts
//     )

//     return (format === 'raw' ?
//         new Uint8Array(encrypted) :
//         arrBufToBase64(encrypted))
// }
