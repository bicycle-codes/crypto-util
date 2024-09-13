import { gcm } from '@noble/ciphers/aes'
import { type Cipher } from '@noble/ciphers/utils'
import { randomBytes } from '@noble/ciphers/webcrypto'
import { fromString, toString } from '../util'

/**
 * Create a new AES key with `@noble` modules.
 *
 * No cofig options; always returns GCM key with 12 byte nonce.
 *
 * @return {Cipher} AES key
 */
export function create ():Cipher {
    const key = randomBytes(32) // 24 for AES-192, 16 for AES-128
    const nonce = randomBytes(12)
    const aes = gcm(key, nonce)
    return aes
}

export function importKey (
    key:string|Uint8Array,
    nonce:string|Uint8Array
):Cipher {
    const buf = typeof key === 'string' ? fromString(key) : key
    const nonceBuf = (typeof nonce === 'string' ?
        fromString(nonce) :
        nonce)

    return gcm(buf, nonceBuf)
}

export function encrypt () {

}

export function decrypt (
    data:string|Uint8Array,
    key:Cipher,
    { format }:{ format:'raw' }
):Uint8Array

export function decrypt (
    data:string|Uint8Array,
    key:Cipher,
    opts?:{ format:'string' }
):string

export function decrypt (data:string|Uint8Array, key:Cipher, {
    format
}:{ format:'string'|'raw' } = { format: 'string' }) {
    if (format === 'string') {
        return toString(key.decrypt(fromString(data)))
    }

    return key.decrypt(fromString(data))
}
