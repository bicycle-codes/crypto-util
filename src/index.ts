import * as uint8arrays from 'uint8arrays'
import { BASE58_DID_PREFIX } from './constants'
import type { DID, KeyAlgorithm } from './types'

export * from './util'
export * from './types'
export * from './constants'
export * from './errors'

export const magicBytes:Record<KeyAlgorithm, Uint8Array> = {
    'bls12-381': new Uint8Array([0xea, 0x01]),
    ed25519: new Uint8Array([0xed, 0x01]),
    rsa: new Uint8Array([0x00, 0xf5, 0x02]),
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
    const prefix = magicBytes[keyType]
    if (!prefix) {
        throw new Error(`Key type '${keyType}' not supported, ` +
            `available types: ${Object.keys(magicBytes).join(', ')}`)
    }

    const prefixedBuf = uint8arrays.concat([prefix, publicKey])

    return (BASE58_DID_PREFIX +
        uint8arrays.toString(prefixedBuf, 'base58btc')) as DID
}
