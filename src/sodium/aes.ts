import libsodium from 'libsodium-wrappers'
import * as u from 'uint8arrays/from-string'
import {
    toString,
    joinBufs,
    randomBuf,
    fromString
} from '../util'

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
    opts?:Partial<{
        iv:Uint8Array
    }>,
):Promise<ArrayBuffer> {
    await libsodium.ready
    const sodium = libsodium

    const data = (typeof msg === 'string' ?
        u.fromString(msg) :
        msg
    )

    const importedKey = (typeof key === 'string' ?
        fromString(key) :
        key)

    const iv = opts?.iv || randomBuf(sodium.crypto_aead_aegis256_NSECBYTES)
    const publicNonce = randomBuf(sodium.crypto_aead_aegis256_NPUBBYTES)
    const cipherBuf = sodium.crypto_aead_aegis256_encrypt(
        data,
        null,
        iv,
        publicNonce,
        importedKey
    )

    return joinBufs(iv, cipherBuf)
}
