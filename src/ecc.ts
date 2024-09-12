import { webcrypto } from '@bicycle-codes/one-webcrypto'
import {
    DEFAULT_CHAR_SIZE,
    DEFAULT_HASH_ALGORITHM,
    ECC_SIGN_ALGORITHM,
    ECC_ENCRYPT_ALGORITHM,
    DEFAULT_ECC_CURVE,
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_SYMM_LEN,
} from './constants'
import { checkValidKeyUse } from './errors'
import type {
    Msg,
    PrivateKey,
    CharSize,
    HashAlg,
    PublicKey,
    SymmKeyLength,
    SymmKey,
    SymmAlg
} from './types'
import {
    KeyUse,
    EccCurve
} from './types'
import * as aes from './aes'
import {
    normalizeUnicodeToBuf,
    normalizeBase64ToBuf,
    arrBufToBase64,
    base64ToArrBuf,
} from './util'

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
    publicKey:string|PublicKey,
    { format }:{ format: 'base64'|'raw' } = { format: 'base64' },
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<{
        alg:SymmAlg
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<Uint8Array|string> {
    const importedPublicKey = typeof publicKey === 'string'
        ? await importPublicKey(publicKey, curve, KeyUse.Encrypt)
        : publicKey

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

async function getPublicKey (keypair:CryptoKeyPair):Promise<string> {
    const raw = await webcrypto.subtle.exportKey('raw', keypair.publicKey)
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
    getPublicKey,
    getSharedKey
}

export async function importPublicKey (
    base64Key:string,
    curve:EccCurve,
    use:KeyUse
):Promise<PublicKey> {
    checkValidKeyUse(use)
    const alg = use === KeyUse.Encrypt ?
        ECC_ENCRYPT_ALGORITHM :
        ECC_SIGN_ALGORITHM
    const uses: KeyUsage[] =
      use === KeyUse.Encrypt ? [] : ['verify']
    const buf = base64ToArrBuf(base64Key)
    return webcrypto.subtle.importKey(
        'raw',
        buf,
        { name: alg, namedCurve: curve },
        true,
        uses
    )
}
