import { webcrypto } from '@bicycle-codes/one-webcrypto'
import {
    DEFAULT_SYMM_ALGORITHM,
    DEFAULT_CTR_LEN,
    DEFAULT_SYMM_LEN,
    DEFAULT_CHAR_SIZE,
} from './constants.js'
import {
    CharSize,
    type CipherText,
    type SymmKey,
    type Msg,
    type SymmKeyLength,
    type SymmKeyOpts,
    type SymmAlg
} from './types.js'
import {
    randomBuf,
    normalizeUtf16ToBuf,
    joinBufs,
    normalizeBase64ToBuf,
    arrBufToBase64,
    arrBufToStr,
    base64ToArrBuf,
    normalizeUtf8ToBuf
} from './util.js'

export async function encryptBytes (
    msg:Msg,
    key:SymmKey|string,
    opts?:Partial<{
        alg:SymmAlg
        length:SymmKeyLength
        iv:ArrayBuffer
    }>,
    charSize:CharSize = DEFAULT_CHAR_SIZE
):Promise<CipherText> {
    const data = (charSize === CharSize.B8 ?
        normalizeUtf8ToBuf(msg) :
        normalizeUtf16ToBuf(msg))

    const importedKey = typeof key === 'string' ? await importKey(key, opts) : key
    const alg = opts?.alg || DEFAULT_SYMM_ALGORITHM
    const iv = opts?.iv || randomBuf(12)
    const cipherBuf = await webcrypto.subtle.encrypt(
        {
            name: alg,
            // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
            iv: alg === 'AES-CTR' ? undefined : iv,
            counter: alg === 'AES-CTR' ? new Uint8Array(iv) : undefined,
            length: alg === 'AES-CTR' ? DEFAULT_CTR_LEN : undefined,
        },
        importedKey,
        data
    )

    return joinBufs(iv, cipherBuf)
}

export async function decryptBytes (
    msg: Msg,
    key: SymmKey | string,
    opts?: Partial<SymmKeyOpts>
):Promise<ArrayBuffer> {
    const cipherText = normalizeBase64ToBuf(msg)
    const importedKey = typeof key === 'string' ? await importKey(key, opts) : key
    const alg = opts?.alg || DEFAULT_SYMM_ALGORITHM
    const iv = cipherText.slice(0, 12)
    const cipherBytes = cipherText.slice(12)
    const msgBuff = await webcrypto.subtle.decrypt(
        {
            name: alg,
            // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
            iv: alg === 'AES-CTR' ? undefined : iv,
            counter: alg === 'AES-CTR' ? new Uint8Array(iv) : undefined,
            length: alg === 'AES-CTR' ? DEFAULT_CTR_LEN : undefined,
        },
        importedKey,
        cipherBytes
    )
    return msgBuff
}

export async function encrypt (
    msg:Msg,
    key:SymmKey|string,
    opts?:Partial<SymmKeyOpts>
): Promise<string> {
    const cipherText = await encryptBytes(msg, key, opts)
    return arrBufToBase64(cipherText)
}

export async function decrypt (
    msg:Msg,
    key:SymmKey|string,
    opts?:Partial<SymmKeyOpts>,
    charSize:CharSize = DEFAULT_CHAR_SIZE
):Promise<string> {
    const msgBytes = await decryptBytes(msg, key, opts)
    return arrBufToStr(msgBytes, charSize)
}

export async function exportKey (key:SymmKey):Promise<Uint8Array> {
    const raw = await webcrypto.subtle.exportKey('raw', key)
    return new Uint8Array(raw)
}

export default {
    encryptBytes,
    decryptBytes,
    encrypt,
    decrypt,
    exportKey
}

export async function importKey (
    key:string|Uint8Array,
    opts?:Partial<SymmKeyOpts>
):Promise<SymmKey> {
    const buf = typeof key === 'string' ? base64ToArrBuf(key) : key

    return webcrypto.subtle.importKey(
        'raw',
        buf,
        {
            name: opts?.alg || DEFAULT_SYMM_ALGORITHM,
            length: opts?.length || DEFAULT_SYMM_LEN,
        },
        true,
        ['encrypt', 'decrypt']
    )
}

/**
 * Create a new AES key.
 */
export function create (opts:{ alg, length } = {
    alg: DEFAULT_SYMM_ALGORITHM,
    length: DEFAULT_SYMM_LEN
}) {
    return webcrypto.subtle.generateKey({
        name: opts.alg,
        length: opts.length
    }, true, ['encrypt', 'decrypt'])
}
