import * as uint8arrays from 'uint8arrays'
import { BASE58_DID_PREFIX } from './constants'
import type { DID, KeyTypes } from './types'

export * from './util'
export * from './types'
export * from './constants'
export * from './errors'

export const did:{ keyTypes:KeyTypes } = {
    keyTypes: {
        'bls12-381': {
            magicBytes: new Uint8Array([0xea, 0x01]),
        },

        ed25519: {
            magicBytes: new Uint8Array([0xed, 0x01]),
        },

        rsa: {
            magicBytes: new Uint8Array([0x00, 0xf5, 0x02]),
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
