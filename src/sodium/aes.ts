import libsodium from 'libsodium-wrappers'
import * as u from 'uint8arrays'
import {
    toString,
    joinBufs,
    randomBuf,
    fromString
} from '../util.js'

export async function create ():Promise<string>
export async function create (opts:{
    format:'raw'
}):Promise<Uint8Array>

/**
 * Create a new AES key.
 *
 * @see {@link https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm#warning sodium docs}
 * @param opts Can pass in the `format` for the return value.
 * @returns A new key.
 */
export async function create (opts:{
    format: 'string'|'raw'
} = { format: 'string' }):Promise<Uint8Array|string> {
    await libsodium.ready
    const sodium = libsodium
    const arr = sodium.crypto_aead_aegis256_keygen()

    if (opts.format === 'string') {
        return toString(arr)
    }

    return arr
}

export async function encrypt (
    msg:Uint8Array|string,
    key:Uint8Array|string,
):Promise<string>

export async function encrypt (
    msg:Uint8Array|string,
    key:Uint8Array|string,
    opts:{ format: 'raw' }
):Promise<Uint8Array>

/**
 * Encrypt the given string with the given key.
 */
export async function encrypt (
    msg:Uint8Array|string,
    key:Uint8Array|string,
    opts:Partial<{
        iv?:Uint8Array
        format?:'string'|'raw'
    }> = { format: 'string' },
):Promise<Uint8Array|string> {
    await libsodium.ready
    const sodium = libsodium

    const data = (typeof msg === 'string' ?
        u.fromString(msg) :
        msg
    )

    const importedKey = (typeof key === 'string' ?
        fromString(key) :
        key)

    const pubNonce = opts?.iv || randomBuf(sodium.crypto_aead_aegis256_NPUBBYTES)
    const cipherBuf = sodium.crypto_aead_aegis256_encrypt(
        data,
        null,
        null,
        pubNonce,
        importedKey
    )

    const joined = joinBufs(pubNonce, cipherBuf)

    if (opts.format === 'string') {
        return toString(joined)
    }

    return joined
}

export async function decrypt (
    cipherText:string|Uint8Array,
    key:string|Uint8Array,
    opts:{ format:'raw' }
):Promise<Uint8Array>

export async function decrypt (
    cipherText:string|Uint8Array,
    key:string|Uint8Array,
):Promise<string>

export async function decrypt (
    cipherText:string|Uint8Array,
    key:string|Uint8Array,
    opts:{ format:'string'|'raw' } = { format: 'string' }
):Promise<Uint8Array|string> {
    await libsodium.ready
    const sodium = libsodium
    const keyBuf = (typeof key === 'string' ? fromString(key) : key)
    const cipherTextBuf = (typeof cipherText === 'string' ?
        fromString(cipherText) :
        cipherText)

    const nonceSize = sodium.crypto_aead_aegis256_NPUBBYTES
    const pubNonce = cipherTextBuf.slice(0, nonceSize)
    const cipherBytes = cipherTextBuf.slice(nonceSize)
    const dec = sodium.crypto_aead_aegis256_decrypt(
        null,
        cipherBytes,
        null,
        pubNonce,
        keyBuf,
    )

    if (opts.format === 'string') {
        return u.toString(dec)
    }

    return dec
}
