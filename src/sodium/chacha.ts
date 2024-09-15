import libsodium from 'libsodium-wrappers'
import { toString } from '../util'

export async function create () {
    await libsodium.ready
    const sodium = libsodium

    const nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES)
    nonce.set(sodium.randombytes_buf(nonce.length))
    const key = sodium.crypto_aead_chacha20poly1305_keygen()
}
