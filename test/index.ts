import { test } from '@bicycle-codes/tapzero'
import { fromString, toString } from 'uint8arrays'
// import { toString } from 'uint8arrays'
import { create as createAes, exportKey as exportAesKey } from '../src/aes.js'
// import { create as createAes } from '../src/aes.js'
import {
    create as createRsa,
    sign as rsaSign,
    encrypt as rsaEncrypt,
    decrypt as rsaDecrypt,
    // decryptKey
} from '../src/rsa.js'
// import { arrBufToBase64, base64ToArrBuf } from '../src/index.js'
import { arrBufToBase64 } from '../src/index.js'
import { KeyUse } from '../src/types.js'

//
// AES
//
let aesKey:CryptoKey
test('Create an AES key', async t => {
    aesKey = await createAes()
    t.ok(aesKey instanceof CryptoKey, 'Should return a CryptoKey')
})

//
// RSA
//
let rsaKeypair:CryptoKeyPair
test('Create an RSA keypair', async t => {
    const keys = rsaKeypair = await createRsa(KeyUse.Sign)
    t.ok(keys.privateKey instanceof CryptoKey, 'should create a new keypair')
    t.ok(keys.publicKey instanceof CryptoKey, 'should create a new keypair')
})

// sign things
test('sign things with RSA', async t => {
    const sig = await rsaSign('hello RSA', rsaKeypair.privateKey)
    const sigString = arrBufToBase64(sig)
    t.ok(sig, 'should return a signature')
    t.equal(sigString.length, 344, 'signature should be 344 characters')
    t.equal(typeof sigString, 'string', 'should convert to a string')
})

// encrypt things
let encryptedKey:string
let aesString:string
let encKeys:CryptoKeyPair
test('encrypt an AES key with RSA', async t => {
    // need to make new RSA keys because the existing keys are for signing
    encKeys = await createRsa(KeyUse.Encrypt)
    const aesArr = await exportAesKey(aesKey)
    aesString = toString(aesArr, 'base64pad')
    console.log('**aes**', aesString)
    encryptedKey = await rsaEncrypt(aesArr, encKeys.publicKey)
    console.log('**encrypted key**', encryptedKey)

    t.equal(typeof encryptedKey, 'string', 'should return a string by default')
})

// test('decrypt an AES key', async t => {
//     const decrypted = await decryptKey(encryptedKey, encKeys)
//     t.ok(decrypted instanceof CryptoKey, 'should return a CryptoKey')
// })

test('decrypt an AES key', async t => {
    const decrypted = await rsaDecrypt(
        // new Uint8Array(base64ToArrBuf(encryptedKey)),
        fromString(encryptedKey, 'base64pad'),
        encKeys.privateKey
    )
    t.ok(decrypted instanceof Uint8Array,
        'should return a Uint8Array by default')

    // const decryptedAsString = await rsaDecrypt(encryptedKey, encKeys.privateKey, {
    //     format: 'base64'
    // })

    // const encrypted = fromString(encryptedKey, 'base64pad')
    const decryptedAsString = toString(decrypted, 'base64pad')

    t.equal(typeof decryptedAsString, 'string', 'can ask for return value as string')
    t.equal(decryptedAsString, aesString, 'should decrypt to the right value')
})

//
// ECC
//
