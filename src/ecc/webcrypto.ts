import { webcrypto } from '@bicycle-codes/one-webcrypto'
import * as uint8arrays from 'uint8arrays'
import { magicBytes, didToPublicKey } from '../index.js'
import {
    BASE58_DID_PREFIX,
    DEFAULT_CHAR_SIZE,
    DEFAULT_HASH_ALGORITHM,
    ECC_SIGN_ALGORITHM,
    ECC_ENCRYPT_ALGORITHM,
    DEFAULT_ECC_CURVE,
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_SYMM_LEN,
} from '../constants.js'
import { checkValidKeyUse } from '../errors.js'
import type {
    Msg,
    PrivateKey,
    CharSize,
    HashAlg,
    PublicKey,
    SymmKeyLength,
    SymmKey,
    SymmAlg,
    DID
} from '../types.js'
import {
    KeyUse,
    EccCurve
} from '../types.js'
import * as aes from '../aes/webcrypto.js'
import {
    normalizeUnicodeToBuf,
    normalizeBase64ToBuf,
    arrBufToBase64,
    base64ToArrBuf,
} from '../util.js'

/**
 * Create a new keypair.
 */
export async function create (
    use:KeyUse,
    curve:EccCurve = EccCurve.P_256,
):Promise<CryptoKeyPair> {
    checkValidKeyUse(use)
    const alg = (use === KeyUse.Encrypt ?
        ECC_ENCRYPT_ALGORITHM :
        ECC_SIGN_ALGORITHM)
    const uses:KeyUsage[] = (use === KeyUse.Encrypt ?
        ['deriveKey', 'deriveBits'] :
        ['sign', 'verify'])

    return webcrypto.subtle.generateKey(
        { name: alg, namedCurve: curve },
        false,
        uses
    )
}

export async function sign (
    msg:Msg,
    privateKey:PrivateKey,
    { format }?:{ format: 'base64' },
    charSize?:CharSize,
    hashAlg?:HashAlg,
):Promise<string>

export async function sign (
    msg:Msg,
    privateKey:PrivateKey,
    { format }:{ format: 'raw' },
    charSize?:CharSize,
    hashAlg?:HashAlg,
):Promise<ArrayBuffer>

/**
 * Sign the given message. Return the signature as an `ArrayBuffer`.
 */
export async function sign (
    msg:Msg,
    privateKey:PrivateKey,
    { format }:{ format: 'base64'|'raw' } = { format: 'base64' },
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM,
):Promise<ArrayBuffer|string> {
    const sig = await webcrypto.subtle.sign(
        { name: ECC_SIGN_ALGORITHM, hash: { name: hashAlg } },
        privateKey,
        normalizeUnicodeToBuf(msg, charSize)
    )

    if (format === 'base64') {
        return arrBufToBase64(sig)
    }

    return sig
}

/**
 * Verify the given signature.
 */
export async function verify (
    msg:Msg,
    sig:string|Uint8Array|ArrayBuffer,
    publicKey:string|PublicKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    hashAlg: HashAlg = DEFAULT_HASH_ALGORITHM
):Promise<boolean> {
    return webcrypto.subtle.verify(
        { name: ECC_SIGN_ALGORITHM, hash: { name: hashAlg } },
        (typeof publicKey === 'string'
            ? await importPublicKey(publicKey, curve, KeyUse.Sign)
            : publicKey),
        normalizeBase64ToBuf(sig),
        normalizeUnicodeToBuf(msg, charSize)
    )
}

// return Uint8Array given 'raw' format
export async function encrypt (
    msg:Msg,
    privateKey:PrivateKey,
    publicKey:string | PublicKey,
    { format }:{ format:'raw' },
    charSize?:CharSize,
    curve?:EccCurve,
    opts?:Partial<{
        alg:SymmAlg
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<Uint8Array>

// return a string otherwise
export async function encrypt (
    msg:Msg,
    privateKey:PrivateKey,
    publicKey:string | PublicKey,
    { format }?,
    charSize?:CharSize,
    curve?:EccCurve,
    opts?:Partial<{
        alg:SymmAlg
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<string>

/**
 * Encrypt the given message.
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

/**
 * Decrypt the given message
 */
export async function decrypt (
    msg:Msg,
    privateKey:PrivateKey,
    publicKey:string|PublicKey,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<{
        alg:'AES-GCM'|'AES-CBC'|'AES-CTR'
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<string> {
    const importedPublicKey = typeof publicKey === 'string'
        ? await importPublicKey(publicKey, curve, KeyUse.Encrypt)
        : publicKey

    const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
    return aes.decrypt(msg, cipherKey, opts)
}

export async function exportPublicKey (
    key:PublicKey,
):Promise<Uint8Array>

export async function exportPublicKey (
    publicKey:PublicKey,
    opts:{ format:'string' }
):Promise<string>

/**
 * Get the public key as a Uint8Array by default, or a base64 string.
 */
export async function exportPublicKey (
    key:PublicKey,
    opts:{ format:'string'|'raw' } = { format: 'raw' }
):Promise<string|Uint8Array> {
    const raw = await webcrypto.subtle.exportKey('raw', key)
    if (opts.format === 'raw') {
        return new Uint8Array(raw)
    }

    return arrBufToBase64(raw)
}

export async function getSharedKey (
    privateKey:PrivateKey,
    publicKey:PublicKey,
    opts?:Partial<{
        alg:'AES-GCM'|'AES-CBC'|'AES-CTR'
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<SymmKey> {
    return webcrypto.subtle.deriveKey(
        { name: ECC_ENCRYPT_ALGORITHM, public: publicKey },
        privateKey,
        {
            name: opts?.alg || DEFAULT_SYMM_ALGORITHM,
            length: opts?.length || DEFAULT_SYMM_LEN
        },
        false,
        ['encrypt', 'decrypt']
    )
}

export default {
    sign,
    verify,
    encrypt,
    exportPublicKey,
    getSharedKey,
    importPublicKey
}

export function importPublicKey (
    base64Key:string|Uint8Array,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    use:KeyUse = KeyUse.Sign
):Promise<PublicKey> {
    checkValidKeyUse(use)
    const alg = use === KeyUse.Encrypt ?
        ECC_ENCRYPT_ALGORITHM :
        ECC_SIGN_ALGORITHM
    const uses:KeyUsage[] = (use === KeyUse.Encrypt ? [] : ['verify'])
    const buf = (typeof base64Key === 'string' ?
        base64ToArrBuf(base64Key) :
        base64Key)

    return webcrypto.subtle.importKey(
        'raw',
        buf,
        { name: alg, namedCurve: curve },
        true,
        uses
    )
}

/**
 * Convert a DID format string to a public key instance.
 */
export async function importDid (did:DID):Promise<PublicKey> {
    const parsed = didToPublicKey(did)
    const pubKey = await importPublicKey(parsed.publicKey)
    return pubKey
}

/**
 * Convert an ed25519 public key to a DID format string.
 */
export async function publicKeyToDid (
    publicKey:Uint8Array|PublicKey
):Promise<DID> {
    if (publicKey instanceof CryptoKey) {
        publicKey = await exportPublicKey(publicKey)
    }

    const prefix = magicBytes.ed25519
    const prefixedBuf = uint8arrays.concat([prefix, publicKey])

    return (BASE58_DID_PREFIX +
        uint8arrays.toString(prefixedBuf, 'base58btc')) as DID
}

/**
 * Verify the given string and signature with the given DID.
 */
export async function verifyWithDid (
    msg:string,
    sig:string,
    did:DID
):Promise<boolean> {
    try {
        const key = didToPublicKey(did).publicKey
        const imported = await importPublicKey(key)
        const isOk = await verify(msg, sig, imported)
        return isOk
    } catch (_err) {
        return false
    }
}
