import { fromString } from 'uint8arrays'
import {
    BASE58_DID_PREFIX,
    RSA_DID_PREFIX,
    KEY_TYPE,
    EDWARDS_DID_PREFIX,
    BLS_DID_PREFIX
} from './constants'
import type { KeyAlgorithm, DID } from './types'

export * from './util'
export * from './types'
export * from './constants'
export * from './errors'

export const magicBytes:Record<KeyAlgorithm, Uint8Array> = {
    'bls12-381': new Uint8Array([0xea, 0x01]),
    ed25519: new Uint8Array([0xed, 0x01]),
    rsa: new Uint8Array([0x00, 0xf5, 0x02]),
}

export function didToPublicKey (did:DID):({
    publicKey:Uint8Array,
    type:'rsa'|'ed25519'|'bls12-381'
}) {
    if (!did.startsWith(BASE58_DID_PREFIX)) {
        throw new Error(
            'Please use a base58-encoded DID formatted `did:key:z...`')
    }

    const didWithoutPrefix = ('' + did.substring(BASE58_DID_PREFIX.length))
    const magicalBuf = fromString(didWithoutPrefix, 'base58btc')
    const { keyBuffer, type } = parseMagicBytes(magicalBuf.buffer)

    return {
        publicKey: new Uint8Array(keyBuffer),
        type
    }
}

/**
 * Parse magic bytes on prefixed key-buffer
 * to determine cryptosystem & the unprefixed key-buffer.
 */
export function parseMagicBytes (prefixedKey:ArrayBuffer) {
    // RSA
    if (hasPrefix(prefixedKey, RSA_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(RSA_DID_PREFIX.byteLength),
            type: KEY_TYPE.RSA
        }
    // EDWARDS
    } else if (hasPrefix(prefixedKey, EDWARDS_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(EDWARDS_DID_PREFIX.byteLength),
            type: KEY_TYPE.Edwards
        }
    // BLS
    } else if (hasPrefix(prefixedKey, BLS_DID_PREFIX)) {
        return {
            keyBuffer: prefixedKey.slice(BLS_DID_PREFIX.byteLength),
            type: KEY_TYPE.BLS
        }
    }

    throw new Error('Unsupported key algorithm. Try using RSA.')
}

function hasPrefix (prefixedKey:ArrayBuffer, prefix:ArrayBuffer) {
    return arrBufsEqual(prefix, prefixedKey.slice(0, prefix.byteLength))
}

function arrBufsEqual (aBuf:ArrayBuffer, bBuf:ArrayBuffer):boolean {
    const a = new Uint8Array(aBuf)
    const b = new Uint8Array(bBuf)
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false
    }
    return true
}
