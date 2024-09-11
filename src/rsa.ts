import { webcrypto } from '@bicycle-codes/one-webcrypto'
import {
    DEFAULT_CHAR_SIZE,
    DEFAULT_HASH_ALGORITHM,
    RSA_SALT_LENGTH,
    RSA_SIGN_ALGORITHM,
    RSA_ALGORITHM,
    RSA_HASHING_ALGORITHM
} from './constants'
import { checkValidKeyUse } from './errors'
import {
    base64ToArrBuf,
    normalizeBase64ToBuf,
    normalizeUnicodeToBuf,
    isCryptoKey,
    publicExponent
} from './util'
import { KeyUse } from './types'
import type { RsaSize, Msg, CharSize, HashAlg } from './types'

export async function verify (
    msg:Msg,
    sig:Msg,
    publicKey:string|CryptoKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM
):Promise<boolean> {
    return webcrypto.subtle.verify({
        name: RSA_SIGN_ALGORITHM,
        saltLength: RSA_SALT_LENGTH
    }, (typeof publicKey === 'string' ?
        await importPublicKey(publicKey, hashAlg, KeyUse.Sign) :
        publicKey),
    normalizeBase64ToBuf(sig),
    normalizeUnicodeToBuf(msg, charSize))
}

export async function sign (
    msg:Msg,
    privateKey:CryptoKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE
):Promise<ArrayBuffer> {
    return webcrypto.subtle.sign(
        { name: RSA_SIGN_ALGORITHM, saltLength: RSA_SALT_LENGTH },
        privateKey,
        normalizeUnicodeToBuf(msg, charSize)
    )
}

export async function rsaEncrypt (
    msg:Msg,
    publicKey:string|CryptoKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM
):Promise<ArrayBuffer> {
    const pubKey = typeof publicKey === 'string' ?
        await importPublicKey(publicKey, hashAlg, KeyUse.Encrypt) :
        publicKey

    return webcrypto.subtle.encrypt(
        { name: RSA_ALGORITHM },
        pubKey,
        normalizeUnicodeToBuf(msg, charSize)
    )
}

export async function rsaDecrypt (
    data:Uint8Array,
    privateKey:CryptoKey|Uint8Array
):Promise<Uint8Array> {
    const key = isCryptoKey(privateKey) ?
        privateKey :
        await importRsaKey(privateKey, ['decrypt'])

    const arrayBuffer = await webcrypto.subtle.decrypt(
        { name: RSA_ALGORITHM },
        key,
        data
    )

    const arr = new Uint8Array(arrayBuffer)

    return arr
}

export async function importPublicKey (
    base64Key:string|ArrayBuffer,
    hashAlg:HashAlg,
    use:KeyUse
):Promise<CryptoKey> {
    checkValidKeyUse(use)
    const alg = (use === KeyUse.Encrypt ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM)
    const uses:KeyUsage[] = use === KeyUse.Encrypt ?
        ['encrypt'] :
        ['verify']
    const buf = typeof base64Key === 'string' ?
        base64ToArrBuf(stripKeyHeader(base64Key)) :
        base64Key

    return webcrypto.subtle.importKey('spki', buf, {
        name: alg,
        hash: { name: hashAlg }
    }, true, uses)
}

function stripKeyHeader (base64Key:string):string {
    return base64Key
        .replace('-----BEGIN PUBLIC KEY-----\n', '')
        .replace('\n-----END PUBLIC KEY-----', '')
}

export function importRsaKey (
    key:Uint8Array,
    keyUsages:KeyUsage[]
):Promise<CryptoKey> {
    return webcrypto.subtle.importKey(
        'spki',
        key,
        { name: RSA_ALGORITHM, hash: RSA_HASHING_ALGORITHM },
        false,
        keyUsages
    )
}

export async function create (
    size:RsaSize,
    hashAlg:HashAlg,
    use:KeyUse
):Promise<CryptoKeyPair> {
    if (!(Object.values(KeyUse).includes(use))) {
        throw new Error('invalid key use')
    }
    const alg = use === KeyUse.Encrypt ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM
    const uses:KeyUsage[] = (use === KeyUse.Encrypt ?
        ['encrypt', 'decrypt'] :
        ['sign', 'verify'])

    return webcrypto.subtle.generateKey({
        name: alg,
        modulusLength: size,
        publicExponent: publicExponent(),
        hash: { name: hashAlg }
    }, false, uses)
}
