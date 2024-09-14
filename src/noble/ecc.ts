import * as ed from '@noble/ed25519'
import { verifyAsync } from '@noble/ed25519'
import * as u from 'uint8arrays'
import { BASE58_DID_PREFIX } from '../constants.js'
import { toString } from '../util'
import { magicBytes, parseMagicBytes } from '../index.js'
import type { DID } from '../types'

export type Keypair = {
    publicKey:Uint8Array;
    privateKey:Uint8Array;
}

/**
 * Create a new keypair.
 */
export async function create ():Promise<Keypair> {
    const privKey = ed.utils.randomPrivateKey()  // Secure random key
    const pubKey = await ed.getPublicKeyAsync(privKey)  // Sync methods below

    return { publicKey: pubKey, privateKey: privKey }
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
    { format }?:{ format:'raw' },
):Promise<Uint8Array>

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

    const sig = await ed.signAsync(msgData, privKey)

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
    const pubBuf = typeof publicKey === 'string' ?
        didToPublicKey(publicKey).publicKey :
        publicKey

    try {
        return (await verifyAsync(sig, msg, pubBuf))
    } catch (_err) {
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
    return (BASE58_DID_PREFIX +
        u.toString(prefixedBuf, 'base58btc')) as DID
}

/**
 * Encrypt the given message. Returns a string by default. Pass
 * `{ format: 'raw' }` to return a `Uint8Array`.
 */
export async function encrypt (
    msg:Msg,
    privateKey:PrivateKey,
    publicKey:string|PublicKey,  // <-- base64 or key
    { format }:{ format: 'base64'|'raw' } = { format: 'base64' },
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<{
        alg:SymmAlg
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<Uint8Array|string> {
    const importedPublicKey = (typeof publicKey === 'string' ?
        await importPublicKey(publicKey, curve, KeyUse.Encrypt) :
        publicKey)

    const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
    const encrypted = await aes.encryptBytes(
        normalizeUnicodeToBuf(msg, charSize),
        cipherKey,
        opts
    )

    return (format === 'raw' ?
        new Uint8Array(encrypted) :
        arrBufToBase64(encrypted))
}
