import libsodium from 'libsodium-wrappers'
import {
    BASE58_DID_PREFIX,
    DEFAULT_CHAR_SIZE,
    DEFAULT_HASH_ALGORITHM,
    ECC_SIGN_ALGORITHM,
    ECC_ENCRYPT_ALGORITHM,
    DEFAULT_ECC_CURVE,
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_SYMM_LEN,
} from './constants'
import type { LockKey } from '../types'
import { generateEntropy } from '../util'

await libsodium.ready
const sodium = libsodium

const IV_BYTE_LENGTH = sodium.crypto_sign_SEEDBYTES
const CURRENT_LOCK_KEY_FORMAT_VERSION = 1

/**
 * Create a new keypair.
 */
export async function create ():Promise<LockKey> {

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
