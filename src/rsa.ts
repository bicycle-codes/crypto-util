import { webcrypto } from '@bicycle-codes/one-webcrypto'
import { fromString, toString } from 'uint8arrays'
import * as uint8arrays from 'uint8arrays'
import { magicBytes, parseMagicBytes } from './index.js'
import {
    BASE58_DID_PREFIX,
    DEFAULT_CHAR_SIZE,
    DEFAULT_HASH_ALGORITHM,
    RSA_SALT_LENGTH,
    RSA_SIGN_ALGORITHM,
    RSA_ALGORITHM,
    RSA_HASHING_ALGORITHM,
    DEFAULT_RSA_SIZE,
    DEFAULT_STRING_ENCODING
} from './constants'
import { checkValidKeyUse } from './errors'
import { importKey as importAesKey } from './aes'
import {
    base64ToArrBuf,
    normalizeBase64ToBuf,
    normalizeUnicodeToBuf,
    isCryptoKey,
    publicExponent,
    arrBufToBase64,
} from './util'
import { KeyUse } from './types'
import type { RsaSize, Msg, CharSize, HashAlg, DID, PublicKey } from './types'

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

export async function encrypt (
    msg:Msg,
    publicKey:string|CryptoKey,
    opts?:{ format:'base64' },
    charSize?:CharSize,
    hashAlg?:HashAlg
):Promise<string>

export async function encrypt (
    msg:Msg,
    publicKey:string|CryptoKey,
    opts:{ format:'base64'|'raw' } = { format: 'base64' },
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM
):Promise<string|Uint8Array> {
    const pubKey = typeof publicKey === 'string' ?
        await importPublicKey(publicKey, hashAlg, KeyUse.Encrypt) :
        publicKey

    const encrypted = await webcrypto.subtle.encrypt(
        { name: RSA_ALGORITHM },
        pubKey,
        normalizeUnicodeToBuf(msg, charSize)
    )

    return (opts.format === 'raw' ?
        new Uint8Array(encrypted) :
        arrBufToBase64(encrypted))
}

/**
 * Decrypt the given Uint8Array
 */
export async function decrypt (
    data:Uint8Array|string,
    privateKey:CryptoKey|Uint8Array
):Promise<Uint8Array> {
    const key = isCryptoKey(privateKey) ?
        privateKey :
        await importPublicKey(privateKey, undefined, KeyUse.Encrypt)

    const arrayBuffer = await webcrypto.subtle.decrypt(
        { name: RSA_ALGORITHM },
        key,
        typeof data === 'string' ? fromString(data, 'base64pad') : data
    )

    const arr = new Uint8Array(arrayBuffer)

    return arr
}

/* Decrypt the given encrypted (AES) key. Get your keys from indexedDB, or use
* the use the passed in key to decrypt the given encrypted AES key.
*
* @param {string} encryptedKey The encrypted key as string
* @param {CryptoKeyPair} keypair The keypair to use to decrypt
* @returns {Promise<CryptoKey>} The symmetric key
*/
export async function decryptKey (
    encryptedKey:string,
    keypair:CryptoKeyPair
):Promise<CryptoKey> {
    const decrypted = await decrypt(
        fromString(encryptedKey),
        keypair.privateKey
    )

    const key = await importAesKey(decrypted)
    return key
}

/**
 * Return a CryptoKey from the given Uint8Array or string.
 */
export async function importPublicKey (
    base64Key:string|Uint8Array,
    hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM,
    use:KeyUse = KeyUse.Encrypt
):Promise<CryptoKey> {
    checkValidKeyUse(use)
    const alg = (use === KeyUse.Encrypt ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM)
    const uses:KeyUsage[] = (use === KeyUse.Encrypt ?
        ['encrypt'] :
        ['verify'])
    const buf = typeof base64Key === 'string' ?
        base64ToArrBuf(stripKeyHeader(base64Key)) :
        base64Key

    return webcrypto.subtle.importKey('spki', buf, {
        name: alg,
        hash: { name: hashAlg }
    }, true, uses)
}

// export async function exportKey (
//     keys:CryptoKeyPair,
//     { format }?:{ format:'raw' }
// ):Promise<string>

export async function exportKey (
    key:PublicKey
):Promise<Uint8Array>

export async function exportKey (
    key:PublicKey,
    opts:{ format:'string' }
):Promise<string>

/**
 * Get a public key from the given keypair.
 *
 * @param keys The keypair to extract the public key from
 * @returns The public key
 */
export async function exportKey (
    key:PublicKey,
    { format }:{ format:'string'|'raw' } = { format: 'raw' }
):Promise<Uint8Array|string> {
    const arr = new Uint8Array(await webcrypto.subtle.exportKey(
        'spki',
        key
    ))

    if (format === 'string') {
        return toString(arr, DEFAULT_STRING_ENCODING)
    }

    return arr
}

export async function create (
    use:KeyUse,
    size:RsaSize = DEFAULT_RSA_SIZE,
    hashAlg:HashAlg = RSA_HASHING_ALGORITHM,
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

function stripKeyHeader (base64Key:string):string {
    return base64Key
        .replace('-----BEGIN PUBLIC KEY-----\n', '')
        .replace('\n-----END PUBLIC KEY-----', '')
}

export async function verifyWithDid (
    msg:string,
    sig:string,
    did:DID
):Promise<boolean> {
    const key = await importDid(did)
    try {
        const isOk = await verify(msg, sig, key)
        return isOk
    } catch (_err) {
        return false
    }
}

/**
 * Convert a public key to a DID format string.
 */
export async function publicKeyToDid (
    publicKey:Uint8Array|PublicKey,
):Promise<DID> {
    if (publicKey instanceof CryptoKey) {
        publicKey = await exportKey(publicKey)
    }

    const prefix = magicBytes.rsa
    const prefixedBuf = uint8arrays.concat([prefix, publicKey])

    return (BASE58_DID_PREFIX +
        uint8arrays.toString(prefixedBuf, 'base58btc')) as DID
}

/**
 * Convert the given DID string to a public key Uint8Array.
 */
export function didToPublicKey (did:DID):({
    publicKey:Uint8Array,
    type:'rsa'
}) {
    if (!did.startsWith(BASE58_DID_PREFIX)) {
        throw new Error(
            'Please use a base58-encoded DID formatted `did:key:z...`')
    }

    const didWithoutPrefix = ('' + did.substring(BASE58_DID_PREFIX.length))
    const magicalBuf = uint8arrays.fromString(didWithoutPrefix, 'base58btc')
    const { keyBuffer } = parseMagicBytes(magicalBuf)

    return {
        publicKey: new Uint8Array(keyBuffer),
        type: 'rsa'
    }
}

/**
 * Convert the given DID string to a public key.
 */
export async function importDid (
    did:DID,
    hashAlgorithm:HashAlg = DEFAULT_HASH_ALGORITHM,
    use:KeyUse = KeyUse.Sign
):Promise<PublicKey> {
    const parsed = didToPublicKey(did)
    const key = await importPublicKey(parsed.publicKey, hashAlgorithm, use)
    return key
}
