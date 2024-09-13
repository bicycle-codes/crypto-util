import * as uint8arrays from 'uint8arrays'
import { webcrypto } from '@bicycle-codes/one-webcrypto'
import type { Msg } from './types'
import { CharSize } from './types'
import { InvalidMaxValue } from './errors'
import { DEFAULT_CHAR_SIZE } from './constants'

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

export function randomBuf (
    length:number,
    { max }:{ max:number } = { max: 255 }
):ArrayBuffer {
    if (max < 1 || max > 255) {
        throw InvalidMaxValue
    }

    const arr = new Uint8Array(length)

    if (max === 255) {
        webcrypto.getRandomValues(arr)
        return arr.buffer
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

    return arr.buffer
}

export function joinBufs (fst:ArrayBuffer, snd:ArrayBuffer):ArrayBuffer {
    const view1 = new Uint8Array(fst)
    const view2 = new Uint8Array(snd)
    const joined = new Uint8Array(view1.length + view2.length)
    joined.set(view1)
    joined.set(view2, view1.length)
    return joined.buffer
}

export function arrBufToBase64 (buf:ArrayBuffer):string {
    return uint8arrays.toString(new Uint8Array(buf), 'base64pad')
}

export function toString (arr:Uint8Array) {
    return uint8arrays.toString(arr, 'base64pad')
}

export function base64ToArrBuf (string:string):ArrayBuffer {
    return uint8arrays.fromString(string, 'base64pad').buffer
}

export async function sha256 (bytes:Uint8Array):Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.digest('sha-256', bytes))
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
    return uint8arrays.fromString(str, 'base64pad')
}
