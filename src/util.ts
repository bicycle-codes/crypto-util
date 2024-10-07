import * as u from 'uint8arrays'
import type libsodium from 'libsodium-wrappers'
import { concat, toString as uToString } from 'uint8arrays'
import { webcrypto } from '@bicycle-codes/one-webcrypto'
import type { KeyAlgorithm, Msg, JSONValue, LockKey, DID } from './types.js'
import { CharSize } from './types.js'
import { InvalidMaxValue } from './errors.js'
import {
    DEFAULT_CHAR_SIZE,
    DEFAULT_ENTROPY_SIZE,
    RSA_DID_PREFIX,
    KEY_TYPE,
    EDWARDS_DID_PREFIX,
    BLS_DID_PREFIX,
    BASE58_DID_PREFIX
} from './constants.js'

export const normalizeToBuf = (
    msg:Msg,
    strConv:(str:string)=>ArrayBuffer
):ArrayBuffer => {
    if (typeof msg === 'string') {
        return strConv(msg)
    } else if (typeof msg === 'object' && msg.byteLength !== undefined) {
        // this is the best runtime check I could find for ArrayBuffer/Uint8Array
        const temp = new Uint8Array(msg)
        return temp.buffer
    } else {
        throw new Error('Improper value. Must be a string, ArrayBuffer, Uint8Array')
    }
}

/**
 * Export the public key from the given keypair as a Uint8Array.
 * @param {CryptoKeyPair} keys The keypair to export.
 * @returns {Promise<Uint8Array>} The public key as Uint8Array.
 */
export async function exportKey (keys:CryptoKeyPair):Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.exportKey(
        'spki',
        keys.publicKey
    ))
}

export function normalizeBase64ToBuf (msg:Msg):ArrayBuffer {
    return normalizeToBuf(msg, base64ToArrBuf)
}

export const normalizeUtf8ToBuf = (msg:Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B8))
}

export const normalizeUtf16ToBuf = (msg:Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B16))
}

export function normalizeUnicodeToBuf (
    msg:Msg,
    charSize:CharSize = DEFAULT_CHAR_SIZE
) {
    switch (charSize) {
        case 8: return normalizeUtf8ToBuf(msg)
        default: return normalizeUtf16ToBuf(msg)
    }
}

export function strToArrBuf (
    str:string,
    charSize:CharSize = DEFAULT_CHAR_SIZE
):ArrayBuffer {
    const view = charSize === 8 ?
        new Uint8Array(str.length) :
        new Uint16Array(str.length)

    for (let i = 0, strLen = str.length; i < strLen; i++) {
        view[i] = str.charCodeAt(i)
    }

    return view.buffer
}

export function generateEntropy (
    sodium:typeof libsodium,
    size:number = DEFAULT_ENTROPY_SIZE
):Uint8Array {
    return sodium.randombytes_buf(size)
}

export function randomBuf (
    length:number,
    { max }:{ max:number } = { max: 255 }
):Uint8Array {
    if (max < 1 || max > 255) {
        throw InvalidMaxValue
    }

    const arr = new Uint8Array(length)

    if (max === 255) {
        webcrypto.getRandomValues(arr)
        return arr
    }

    let index = 0
    const interval = max + 1
    const divisibleMax = Math.floor(256 / interval) * interval
    const tmp = new Uint8Array(1)

    while (index < arr.length) {
        webcrypto.getRandomValues(tmp)
        if (tmp[0] < divisibleMax) {
            arr[index] = tmp[0] % interval
            index++
        }
    }

    return arr
}

export function joinBufs (
    fst:ArrayBuffer|Uint8Array,
    snd:ArrayBuffer|Uint8Array
):Uint8Array {
    const view1 = new Uint8Array(fst)
    const view2 = new Uint8Array(snd)
    const joined = new Uint8Array(view1.length + view2.length)
    joined.set(view1)
    joined.set(view2, view1.length)
    return joined
}

export function arrBufToBase64 (buf:ArrayBuffer):string {
    return u.toString(new Uint8Array(buf), 'base64pad')
}

/**
 * Convert Uint8Arrays to `base64pad` encoded strings.
 *
 * @param {Uint8Array} arr Input `Uint8Array`
 * @returns {string} `base64pad` encoded string
 */
export function toString (arr:Uint8Array) {
    return u.toString(arr, 'base64pad')
}

/**
 * Convert a given string to an `ArrayBuffer`.
 *
 * @param {string} str input string
 * @returns {ArrayBuffer} Array buffer
 */
export function base64ToArrBuf (str:string):ArrayBuffer {
    return u.fromString(str, 'base64pad').buffer
}

export async function sha256 (
    bytes:string|Uint8Array,
    opts?:{ output:'string' }
):Promise<string>

export async function sha256 (
    bytes:string|Uint8Array,
    opts:{ output:'bytes' }
):Promise<Uint8Array>

/**
 * Create a sha-256 hash of the given `Uint8Array`.
 * @param {Uint8Array|string} bytes The input bytes
 * @returns {Promise<Uint8Array>} A `Uint8Array`
 */
export async function sha256 (
    bytes:Uint8Array|string,
    opts:{ output:'string'|'bytes' } = { output: 'string' }
):Promise<Uint8Array|string> {
    let _bytes:Uint8Array
    if (typeof bytes === 'string') {
        _bytes = u.fromString(bytes)
    } else {
        _bytes = bytes
    }

    const hash = new Uint8Array(await webcrypto.subtle.digest('sha-256', _bytes))

    if (opts.output === 'string') {
        return toString(hash)
    }

    return hash
}

export function isCryptoKeyPair (val:unknown):val is CryptoKeyPair {
    return (
        hasProp(((val! as CryptoKeyPair).publicKey), 'algorithm') &&
        hasProp(val, 'publicKey')
    )
}

export function isCryptoKey (val:unknown):val is CryptoKey {
    return (
        hasProp(val, 'algorithm') &&
        hasProp(val, 'extractable') &&
        hasProp(val, 'type')
    )
}

export function hasProp<K extends PropertyKey> (
    data:unknown,
    prop:K
):data is Record<K, unknown> {
    return (typeof data === 'object' && data != null && prop in data)
}

export function arrBufToStr (
    buf:ArrayBuffer,
    charSize:CharSize = DEFAULT_CHAR_SIZE
):string {
    const arr = charSize === 8 ? new Uint8Array(buf) : new Uint16Array(buf)
    return Array.from(arr)
        .map(b => String.fromCharCode(b))
        .join('')
}

export function publicExponent ():Uint8Array {
    return new Uint8Array([0x01, 0x00, 0x01])
}

/**
 * Create a `Uint8Array` from a given `base64pad` encoded string.
 *
 * @param str `base64pad` encoded string
 * @returns {Uint8Array}
 */
export function fromString (str:string) {
    return u.fromString(str, 'base64pad')
}

/**
 * Parse magic bytes on prefixed key-buffer to determine the
 * cryptosystem & the unprefixed key-buffer.
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

export function asBufferOrString (
    data:Uint8Array|ArrayBuffer|string|JSONValue
):Uint8Array|string {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data)
    }

    if (isByteArray(data)) {
        return (data as Uint8Array)
    }

    if (typeof data === 'object') {
        // assume JSON serializable
        return JSON.stringify(data)
    }

    // data must be a string
    return String(data)
}

export function isByteArray (val:unknown):boolean {
    return (val instanceof Uint8Array && val.buffer instanceof ArrayBuffer)
}

export function stringify (keys:LockKey):string {
    return toString(keys.publicKey)
    // => 'welOX9O96R6WH0S8cqqwMlPAJ3VwMgAZEnc1wa1MN70='
}

export const magicBytes:Record<KeyAlgorithm, Uint8Array> = {
    'bls12-381': new Uint8Array([0xea, 0x01]),
    ed25519: new Uint8Array([0xed, 0x01]),
    rsa: new Uint8Array([0x00, 0xf5, 0x02]),
}

export const publicKeyToDid = {
    ecc: function (publicKey:Uint8Array):DID {
        const prefix = magicBytes.ed25519
        const prefixedBuf = concat([prefix, publicKey])

        return (BASE58_DID_PREFIX +
            uToString(prefixedBuf, 'base58btc')) as DID
    },

    rsa: function (publicKey:Uint8Array) {
        const prefix = magicBytes.rsa
        const prefixedBuf = concat([prefix, publicKey])

        return (BASE58_DID_PREFIX +
            uToString(prefixedBuf, 'base58btc')) as DID
    }
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
    const magicalBuf = u.fromString(didWithoutPrefix, 'base58btc')
    const { keyBuffer, type } = parseMagicBytes(magicalBuf.buffer)

    return {
        publicKey: new Uint8Array(keyBuffer),
        type
    }
}
