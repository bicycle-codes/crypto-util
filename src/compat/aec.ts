import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/ciphers/webcrypto'

/**
 * Create a new AES key with `@noble` modules.
 *
 * No cofig options; always returns GCM key with 12 byte nonce.
 *
 * @return AES key
 */
export function create () {
    const key = randomBytes(32) // 24 for AES-192, 16 for AES-128
    const nonce = randomBytes(12)
    const aes = gcm(key, nonce)
    return aes
}
