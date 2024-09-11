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
    EccCurve,
    SymmKeyLength,
    SymmKey,
    SymmAlg
} from './types'
import { KeyUse } from './types'
import * as aes from './aes'
import {
    normalizeUnicodeToBuf,
    normalizeBase64ToBuf,
    arrBufToBase64,
    base64ToArrBuf,
} from './util'

export async function sign (
    msg:Msg,
    privateKey:PrivateKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM,
): Promise<ArrayBuffer> {
    return webcrypto.subtle.sign(
        { name: ECC_SIGN_ALGORITHM, hash: { name: hashAlg } },
        privateKey,
        normalizeUnicodeToBuf(msg, charSize)
    )
}

/**
 * Verify a signature with the webcrypto API.
 */
export async function verify (
    msg:Msg,
    sig:Msg,
    publicKey:string|PublicKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    hashAlg: HashAlg = DEFAULT_HASH_ALGORITHM
): Promise<boolean> {
    return webcrypto.subtle.verify(
        { name: ECC_SIGN_ALGORITHM, hash: { name: hashAlg } },
        typeof publicKey === 'string'
            ? await importPublicKey(publicKey, curve, KeyUse.Sign)
            : publicKey,
        normalizeBase64ToBuf(sig),
        normalizeUnicodeToBuf(msg, charSize)
    )
}

export async function encrypt (
    msg:Msg,
    privateKey:PrivateKey,
    publicKey:string | PublicKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<{
        alg:SymmAlg
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
): Promise<ArrayBuffer> {
    const importedPublicKey = typeof publicKey === 'string'
        ? await importPublicKey(publicKey, curve, KeyUse.Encrypt)
        : publicKey

    const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
    return aes.encryptBytes(normalizeUnicodeToBuf(msg, charSize), cipherKey, opts)
}

export async function decrypt (
    msg:Msg,
    privateKey:PrivateKey,
    publicKey:string|PublicKey,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<{
        alg:'AES-GCM';
        length:SymmKeyLength;
        iv:ArrayBuffer;
    }>
):Promise<ArrayBuffer> {
    const importedPublicKey = typeof publicKey === 'string'
        ? await importPublicKey(publicKey, curve, KeyUse.Encrypt)
        : publicKey

    const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
    return aes.decryptBytes(normalizeBase64ToBuf(msg), cipherKey, opts)
}

export async function getPublicKey (keypair:CryptoKeyPair):Promise<string> {
    const raw = await webcrypto.subtle.exportKey('raw', keypair.publicKey)
    return arrBufToBase64(raw)
}

export async function getSharedKey (
    privateKey:PrivateKey,
    publicKey:PublicKey,
    opts?:Partial<{
        alg:'AES-GCM'|'AES-CBC'|'AES-CTR'
        length: SymmKeyLength
        iv: ArrayBuffer
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
    decrypt,
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
