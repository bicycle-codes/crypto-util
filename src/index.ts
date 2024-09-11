import { webcrypto } from '@bicycle-codes/one-webcrypto'
import * as uint8arrays from 'uint8arrays'
import tweetnacl from 'tweetnacl'
import {
    RSA_SIGN_ALGORITHM,
    BASE58_DID_PREFIX,
    DEFAULT_CHAR_SIZE,
    DEFAULT_HASH_ALGORITHM,
    RSA_SALT_LENGTH,
    RSA_ALGORITHM,
    RSA_HASHING_ALGORITHM
} from './constants'
import { KeyUse } from './types'
import type { DID, KeyTypes, Msg, CharSize, HashAlg } from './types'
import {
    importPublicKey,
    normalizeBase64ToBuf,
    normalizeUnicodeToBuf,
    isCryptoKey,
    importRsaKey
} from './util'
// import { createDebug } from '@bicycle-codes/debug'
// const debug = createDebug()

export const did:{ keyTypes:KeyTypes } = {
    keyTypes: {
        'bls12-381': {
            magicBytes: new Uint8Array([0xea, 0x01]),
            verify: () => { throw new Error('Not implemented') },
        },
        ed25519: {
            magicBytes: new Uint8Array([0xed, 0x01]),
            verify: ed25519Verify,
        },
        rsa: {
            magicBytes: new Uint8Array([0x00, 0xf5, 0x02]),
            verify: rsaVerify,
        },
    }
}

/**
 * Convert a public key to a DID format string.
 *
 * @param {Uint8Array} publicKey Public key as Uint8Array
 * @param {'rsa'|'ed25519'} [keyType] 'rsa' only
 * @returns {DID} A DID format string
 */
export function publicKeyToDid (
    publicKey:Uint8Array,
    keyType:'rsa'|'ed25519' = 'rsa'
):DID {
    // Prefix public-write key
    const prefix = did.keyTypes[keyType]?.magicBytes
    if (!prefix) {
        throw new Error(`Key type '${keyType}' not supported, ` +
            `available types: ${Object.keys(did.keyTypes).join(', ')}`)
    }

    const prefixedBuf = uint8arrays.concat([prefix, publicKey])

    return (BASE58_DID_PREFIX +
        uint8arrays.toString(prefixedBuf, 'base58btc')) as DID
}

export async function ed25519Verify ({
    message,
    publicKey,
    signature
}:{
    message: Uint8Array
    publicKey: Uint8Array
    signature: Uint8Array
}):Promise<boolean> {
    return tweetnacl.sign.detached.verify(message, signature, publicKey)
}

export const rsaOperations = {
    verify: async function rsaVerify (
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
    },

    sign: async function sign (
        msg:Msg,
        privateKey:CryptoKey,
        charSize:CharSize = DEFAULT_CHAR_SIZE
    ):Promise<ArrayBuffer> {
        return webcrypto.subtle.sign(
            { name: RSA_SIGN_ALGORITHM, saltLength: RSA_SALT_LENGTH },
            privateKey,
            normalizeUnicodeToBuf(msg, charSize)
        )
    },

    encrypt: async function rsaEncrypt (
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
    },

    decrypt: async function rsaDecrypt (
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
}

export async function rsaVerify ({
    message,
    publicKey,
    signature
}:{
    message: Uint8Array
    publicKey: Uint8Array
    signature: Uint8Array
}):Promise<boolean> {
    return rsaOperations.verify(
        message,
        signature,
        await webcrypto.subtle.importKey(
            'spki',
            publicKey,
            { name: RSA_SIGN_ALGORITHM, hash: RSA_HASHING_ALGORITHM },
            false,
            ['verify']
        ),
        8
    )
}
