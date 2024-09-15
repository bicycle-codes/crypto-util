import libsodium from 'libsodium-wrappers'
import { toString } from '../util'

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
