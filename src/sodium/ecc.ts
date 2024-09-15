import libsodium from 'libsodium-wrappers'
import * as u from 'uint8arrays'
import type { LockKey, JSONValue } from '../types'
import { generateEntropy, fromString, asBufferOrString, toString } from '../util'

await libsodium.ready
const sodium = libsodium

const IV_BYTE_LENGTH = sodium.crypto_sign_SEEDBYTES
const CURRENT_LOCK_KEY_FORMAT_VERSION = 1

/**
 * Create a new keypair.
 */
export async function create ():Promise<LockKey> {
    const keys = deriveLockKey()
    return keys
}

function deriveLockKey (iv = generateEntropy(IV_BYTE_LENGTH)):LockKey {
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
            asBufferOrString(data),
            pubKey
        )

        return isOk
    } catch (_err) {
        return false
    }
}

export async function sign (data:string|Uint8Array, key:LockKey):Promise<string>

export async function sign (data:string|Uint8Array, key:LockKey, opts:{
    outputFormat:'raw'
}):Promise<Uint8Array>

export async function sign (data:string|Uint8Array, key:LockKey, opts:{
    outputFormat:'string'
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
        outputFormat:'string'|'raw'
    } = { outputFormat: 'string' }
):Promise<string|Uint8Array> {
    const outputFormat = opts.outputFormat

    const sig = sodium.crypto_sign_detached(
        data,
        key.privateKey
    )

    return outputFormat === 'string' ? toString(sig) : sig
}

export function encrypt (data:JSONValue, lockKey:LockKey):string
export function encrypt (data:JSONValue, lockKey:LockKey, { outputFormat }:{
    outputFormat:'string'
}):string
export function encrypt (data:JSONValue, lockKey, { outputFormat }:{
    outputFormat:'raw'
}):Uint8Array

export function encrypt (
    data:JSONValue,
    lockKey:LockKey,
    opts:{
        outputFormat:'string'|'raw';
    } = { outputFormat: 'string' }
):string|Uint8Array {
    const { outputFormat } = opts

    if (data == null) {
        throw new Error('Non-empty data required.')
    }

    try {
        const dataBuffer = asBufferOrString(data)
        const encData = sodium.crypto_box_seal(dataBuffer, lockKey.encPK)

        const output = (outputFormat.toLowerCase() === 'base64') ?
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
export function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    { outputFormat }:{
        outputFormat?:'raw';
        parseJSON:any;
    }
):Uint8Array
export function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    { outputFormat, parseJSON }:{
        outputFormat?:'utf8',
        parseJSON:false
    }
):string
export function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    { outputFormat, parseJSON }:{
        outputFormat:'utf8',
        parseJSON?:true
    }
):JSONValue

export function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    opts:{ outputFormat?:'utf8'|'raw', parseJSON?:boolean } = {
        outputFormat: 'utf8',
        parseJSON: true
    }
):string|Uint8Array|JSONValue {
    const outputFormat = opts.outputFormat || 'utf8'
    const parseJSON = opts.parseJSON ?? true

    const dataBuffer = sodium.crypto_box_seal_open(
        typeof data === 'string' ? fromString(data) : data,
        lockKey.encPK,
        lockKey.encSK
    )

    if (outputFormat === 'utf8') {
        const decodedData = u.toString(dataBuffer, 'utf-8')
        return (parseJSON ? JSON.parse(decodedData) : decodedData)
    }

    return dataBuffer
}
