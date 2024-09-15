import libsodium from 'libsodium-wrappers'
import * as u from 'uint8arrays'
import type { LockKey, JSONValue, DID } from '../types'
import { BASE58_DID_PREFIX } from '../constants'
import {
    generateEntropy,
    fromString,
    asBufferOrString,
    toString,
    stringify,
    magicBytes,
} from '../util'
import { didToPublicKey } from '../index.js'
// import Debug from '@bicycle-codes/debug'
// const debug = Debug()

export { stringify }

const CURRENT_LOCK_KEY_FORMAT_VERSION = 1

export function importPublicKey (key:string):Uint8Array {
    return fromString(key)
}

/**
 * Convert a public key to a DID format string.
 */
export async function publicKeyToDid (
    publicKey:Uint8Array
):Promise<DID> {
    const prefix = magicBytes.ed25519
    const prefixedBuf = u.concat([prefix, publicKey])

    return (BASE58_DID_PREFIX +
        u.toString(prefixedBuf, 'base58btc')) as DID
}

/**
 * Convert a DID format string to a public key instance.
 */
export async function importDid (did:DID):Promise<Uint8Array> {
    const parsed = didToPublicKey(did)
    const pubKey = parsed.publicKey
    return pubKey
}

/**
 * Create a new keypair.
 */
export async function create ():Promise<LockKey> {
    const keys = await deriveLockKey()
    return keys
}

async function deriveLockKey (iv?:Uint8Array):Promise<LockKey> {
    await libsodium.ready
    const sodium = libsodium

    const IV_BYTE_LENGTH = sodium.crypto_sign_SEEDBYTES
    if (!iv) {
        iv = generateEntropy(sodium, IV_BYTE_LENGTH)
    }

    try {
        const ed25519KeyPair = sodium.crypto_sign_seed_keypair(iv)

        return {
            keyFormatVersion: CURRENT_LOCK_KEY_FORMAT_VERSION,
            iv,
            publicKey: ed25519KeyPair.publicKey,
            privateKey: ed25519KeyPair.privateKey,
            encPK: sodium.crypto_sign_ed25519_pk_to_curve25519(
                ed25519KeyPair.publicKey,
            ),
            encSK: sodium.crypto_sign_ed25519_sk_to_curve25519(
                ed25519KeyPair.privateKey,
            ),
        }
    } catch (err) {
        throw new Error('Encryption/decryption key derivation failed.', {
            cause: err,
        })
    }
}

/**
 * Verify a given signature and message.
 */
export async function verify (
    data:string|Uint8Array,
    sig:string|Uint8Array,
    keys:{ publicKey:Uint8Array|string }
):Promise<boolean> {
    await libsodium.ready
    const sodium = libsodium

    try {
        const pubKey = (typeof keys.publicKey === 'string' ?
            fromString(keys.publicKey) :
            keys.publicKey)

        const isOk = sodium.crypto_sign_verify_detached(
            typeof sig === 'string' ? fromString(sig) : sig,
            data,
            pubKey
        )

        return isOk
    } catch (_err) {
        return false
    }
}

export async function sign (data:string|Uint8Array, key:LockKey):Promise<string>

export async function sign (data:string|Uint8Array, key:LockKey, opts:{
    format:'raw'
}):Promise<Uint8Array>

export async function sign (data:string|Uint8Array, key:LockKey, opts:{
    format:'string'
}):Promise<string>

/**
 * Sign the given data.
 *
 * Async to match the webcrypto API.
 *
 * @param data The data to sign.
 * @param key The keys to use
 * @param opts Can specify 'raw' as `outputFormat`, which will return
 * a `Uint8Array` instead of a string.
 * @returns {Promise<string|Uint8Array>} String or binary, depending on `opts`
 */
export async function sign (
    data:string|Uint8Array,
    key:LockKey,
    opts:{
        format:'string'|'raw'
    } = { format: 'string' }
):Promise<string|Uint8Array> {
    const outputFormat = opts.format
    await libsodium.ready
    const sodium = libsodium

    const sig = sodium.crypto_sign_detached(
        data,
        key.privateKey
    )

    return outputFormat === 'string' ? toString(sig) : sig
}

export async function encrypt (data:JSONValue, lockKey:LockKey):Promise<string>
export async function encrypt (data:JSONValue, lockKey:LockKey, { outputFormat }:{
    outputFormat:'string'
}):Promise<string>
export async function encrypt (data:JSONValue, lockKey, { outputFormat }:{
    outputFormat:'raw'
}):Promise<Uint8Array>

export async function encrypt (
    data:JSONValue,
    lockKey:LockKey,
    opts:{
        outputFormat:'string'|'raw';
    } = { outputFormat: 'string' }
):Promise<string|Uint8Array> {
    await libsodium.ready
    const sodium = libsodium
    const { outputFormat } = opts

    if (data == null) {
        throw new Error('Non-empty data required.')
    }

    try {
        const dataBuffer = asBufferOrString(data)
        const encData = sodium.crypto_box_seal(dataBuffer, lockKey.encPK)

        const output = (outputFormat.toLowerCase() === 'string') ?
            toString(encData) :
            encData

        return output
    } catch (err) {
        throw new Error('Data encryption failed.', { cause: err })
    }
}

/**
 * If called with { parseJSON: false }, will return
 * a string.
 *
 * If called with { outputFormat: 'raw' }, will return
 * a Uint8Array.
 */
export async function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    { outputFormat }:{
        outputFormat:'raw';
    }
):Promise<Uint8Array>
export async function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    opts?:{
        outputFormat:'utf8',
    }
):Promise<string>

export async function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    opts:{ outputFormat?:'utf8'|'raw' } = {
        outputFormat: 'utf8'
    }
):Promise<string|Uint8Array|JSONValue> {
    await libsodium.ready
    const sodium = libsodium
    const outputFormat = opts.outputFormat || 'utf8'

    const dataBuffer = sodium.crypto_box_seal_open(
        typeof data === 'string' ? fromString(data) : data,
        lockKey.encPK,
        lockKey.encSK
    )

    if (outputFormat === 'utf8') {
        const decodedData = u.toString(dataBuffer, 'utf-8')
        return decodedData
    }

    return dataBuffer
}
