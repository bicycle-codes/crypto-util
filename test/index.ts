import { test } from '@bicycle-codes/tapzero'
import { fromString, toString } from 'uint8arrays'
import {
    create as createAes,
    exportKey as exportAesKey,
    encrypt as aesEncrypt,
    decrypt as aesDecrypt
} from '../src/aes.js'
import {
    create as createRsa,
    sign as rsaSign,
    encrypt as rsaEncrypt,
    decrypt as rsaDecrypt,
} from '../src/rsa.js'
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

let aesEncryptedText:string
test('encrypt some text with AES', async t => {
    aesEncryptedText = await aesEncrypt('hello AES', aesKey)
    t.equal(typeof aesEncryptedText, 'string', 'should return a string')
})

test('decrypt the text with AES', async t => {
    const decrypted = await aesDecrypt(aesEncryptedText, aesKey)
    t.equal(decrypted, 'hello AES', 'should decrypt to the right text')
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
    encryptedKey = await rsaEncrypt(aesArr, encKeys.publicKey)

    t.equal(typeof encryptedKey, 'string', 'should return a string by default')
})

test('decrypt a string AES key', async t => {
    const decrypted = await rsaDecrypt(encryptedKey, encKeys.privateKey)
    t.equal(toString(decrypted, 'base64pad'), aesString,
        'should be able to decrypt a key given as a string')
})

test('decrypt a Uint8Array AES key', async t => {
    const decrypted = await rsaDecrypt(
        fromString(encryptedKey, 'base64pad'),
        encKeys.privateKey
    )
    t.ok(decrypted instanceof Uint8Array,
        'should return a Uint8Array by default')

    const decryptedAsString = toString(decrypted, 'base64pad')

    t.equal(typeof decryptedAsString, 'string', 'can ask for return value as string')
    t.equal(decryptedAsString, aesString, 'should decrypt to the right value')
})

//
// ECC
//
