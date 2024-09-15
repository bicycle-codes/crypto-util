import { fromString } from 'uint8arrays'
import {
    BASE58_DID_PREFIX,
} from './constants'
import type { DID } from './types'
import { parseMagicBytes } from './util'

export * from './util'
export * from './types'
export * from './constants'
export * from './errors'

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
