import { webcrypto } from '@bicycle-codes/one-webcrypto'
import * as uint8arrays from 'uint8arrays'
import tweetnacl from 'tweetnacl'
import {
    RSA_SIGN_ALGORITHM,
    BASE58_DID_PREFIX,
    RSA_ALGORITHM,
} from './constants'
import { checkValidKeyUse } from './errors'
import { KeyUse, HashAlg } from './types'
import type { DID, KeyTypes, } from './types'
import {
    base64ToArrBuf
} from './util'
import { verify as rsaVerify } from './rsa'

export * from './util'
export * from './types'
export * from './constants'
export * from './errors'

export const did:{ keyTypes:KeyTypes } = {
    keyTypes: {
        'bls12-381': {
            magicBytes: new Uint8Array([0xea, 0x01]),
            verify: () => { throw new Error('Not implemented') },
        },

        ed25519: {
            magicBytes: new Uint8Array([0xed, 0x01]),
            verify: async function ed25519Verify ({
                message,
                publicKey,
                signature
            }:{
                message:Uint8Array
                publicKey:Uint8Array
                signature:Uint8Array
            }):Promise<boolean> {
                return tweetnacl.sign.detached.verify(message, signature, publicKey)
            }

        },

        rsa: {
            magicBytes: new Uint8Array([0x00, 0xf5, 0x02]),
            verify: async ({ message, publicKey, signature }:{
                message:Uint8Array,
                publicKey:Uint8Array,
                signature:Uint8Array
            }) => {
                return rsaVerify(
                    message,
                    signature,
                    await importPublicKey(
                        publicKey,
                        HashAlg.SHA_256,
                        KeyUse.Encrypt
                    )
                )
            }
        }
    }
}

/**
 * Convert a public key to a DID format string.
 *
 * @param {Uint8Array} publicKey Public key as Uint8Array
 * @param {'rsa'|'ed25519'} [keyType] 'rsa' or 'ed25519'
 * @returns {DID} A DID format string
 */
export function publicKeyToDid (
    publicKey:Uint8Array,
    keyType:'rsa'|'ed25519' = 'rsa'
):DID {
    const prefix = did.keyTypes[keyType]?.magicBytes
    if (!prefix) {
        throw new Error(`Key type '${keyType}' not supported, ` +
            `available types: ${Object.keys(did.keyTypes).join(', ')}`)
    }

    const prefixedBuf = uint8arrays.concat([prefix, publicKey])

    return (BASE58_DID_PREFIX +
        uint8arrays.toString(prefixedBuf, 'base58btc')) as DID
}

export async function importPublicKey (
    base64Key:string|ArrayBuffer,
    hashAlg:HashAlg,
    use:KeyUse
):Promise<CryptoKey> {
    checkValidKeyUse(use)
    const alg = (use === KeyUse.Encrypt ? RSA_ALGORITHM : RSA_SIGN_ALGORITHM)
    const uses:KeyUsage[] = use === KeyUse.Encrypt ?
        ['encrypt'] :
        ['verify']
    const buf = typeof base64Key === 'string' ?
        base64ToArrBuf(stripKeyHeader(base64Key)) :
        base64Key

    return webcrypto.subtle.importKey('spki', buf, {
        name: alg,
        hash: { name: hashAlg }
    }, true, uses)
}

function stripKeyHeader (base64Key:string):string {
    return base64Key
        .replace('-----BEGIN PUBLIC KEY-----\n', '')
        .replace('\n-----END PUBLIC KEY-----', '')
}
