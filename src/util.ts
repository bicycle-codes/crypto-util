import * as uint8arrays from 'uint8arrays'
import { webcrypto } from '@bicycle-codes/one-webcrypto'
import type { Msg, HashAlg } from './types'
import { KeyUse, CharSize } from './types'
import {
    RSA_HASHING_ALGORITHM,
    RSA_ALGORITHM,
    RSA_SIGN_ALGORITHM,
} from './constants.js'
import { InvalidMaxValue, checkValidKeyUse } from './errors'

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

export function normalizeBase64ToBuf (msg:Msg):ArrayBuffer {
    return normalizeToBuf(msg, base64ToArrBuf)
}

export const normalizeUtf8ToBuf = (msg:Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B8))
}

export const normalizeUtf16ToBuf = (msg:Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B16))
}

export function normalizeUnicodeToBuf (msg:Msg, charSize:CharSize) {
    switch (charSize) {
        case 8: return normalizeUtf8ToBuf(msg)
        default: return normalizeUtf16ToBuf(msg)
    }
}

export function strToArrBuf (str:string, charSize:CharSize):ArrayBuffer {
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

export function importRsaKey (
    key:Uint8Array,
    keyUsages:KeyUsage[]
):Promise<CryptoKey> {
    return webcrypto.subtle.importKey(
        'spki',
        key,
        { name: RSA_ALGORITHM, hash: RSA_HASHING_ALGORITHM },
        false,
        keyUsages
    )
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

export function base64ToArrBuf (string:string):ArrayBuffer {
    return uint8arrays.fromString(string, 'base64pad').buffer
}

export async function sha256 (bytes:Uint8Array):Promise<Uint8Array> {
    return new Uint8Array(await webcrypto.subtle.digest('sha-256', bytes))
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

export function isCryptoKeyPair (val:unknown):val is CryptoKeyPair {
    return (
        hasProp(val, 'algorithm') &&
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
