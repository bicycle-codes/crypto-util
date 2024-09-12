import { test } from '@bicycle-codes/tapzero'
import { toString } from 'uint8arrays'
import {
    create as createAes,
    exportKey as exportAesKey,
    encrypt as aesEncrypt,
    decrypt as aesDecrypt
} from '../src/aes.js'
import {
    create as createEcc,
    sign as eccSign,
    verify as eccVerify,
    getSharedKey,
    decrypt as eccDecrypt,
    encrypt as eccEncrypt
} from '../src/ecc.js'
import {
    create as createRsa,
    sign as rsaSign,
    encrypt as rsaEncrypt,
    decrypt as rsaDecrypt,
} from '../src/rsa.js'
// import { create } from '../src/ecc.js'
import { arrBufToBase64, isCryptoKeyPair } from '../src/index.js'
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
test('RSA encrypt an AES key', async t => {
    // need to make new RSA keys because the existing keys are for signing
    encKeys = await createRsa(KeyUse.Encrypt)
    const aesArr = await exportAesKey(aesKey)
    aesString = toString(aesArr, 'base64pad')
    encryptedKey = await rsaEncrypt(aesArr, encKeys.publicKey)

    t.equal(typeof encryptedKey, 'string', 'should return a string by default')
})

test('RSA decrypt a string AES key', async t => {
    const decrypted = await rsaDecrypt(encryptedKey, encKeys.privateKey)
    t.equal(toString(decrypted, 'base64pad'), aesString,
        'decrypted string should equal the original')
})

test('RSA decrypt a Uint8Array AES key', async t => {
    const decrypted = await rsaDecrypt(
        encryptedKey,
        encKeys.privateKey
    )
    t.ok(decrypted instanceof Uint8Array,
        'should return a Uint8Array by default')

    const decryptedAsString = toString(decrypted, 'base64pad')
    t.equal(decryptedAsString, aesString, 'should decrypt to the right value')
})

//
// ECC
//

let eccKeypair:CryptoKeyPair
let eccSignKeys:CryptoKeyPair
test('create an ECC keypair', async t => {
    eccKeypair = await createEcc(KeyUse.Encrypt)
    eccSignKeys = await createEcc(KeyUse.Sign)
    t.ok(isCryptoKeyPair(eccKeypair), 'should return a new keypair')
})

// sign
let eccSig:string
test('sign something', async t => {
    eccSig = await eccSign('hello ecc', eccSignKeys.privateKey)
    t.equal(typeof eccSig, 'string', 'should return a string by default')
})

test('verify the signature', async t => {
    const isValid = await eccVerify('hello ecc', eccSig, eccSignKeys.publicKey)
    t.equal(isValid, true, 'should validate a valid signature')
})

let BobsKeys:CryptoKeyPair
let sharedKey:CryptoKey
test('Get a shared key from 2 keypairs', async t => {
    BobsKeys = await createEcc(KeyUse.Encrypt)
    sharedKey = await getSharedKey(eccKeypair.privateKey, BobsKeys.publicKey)
    t.ok(sharedKey instanceof CryptoKey, 'should return a `CryptoKey`')
})

let eccEncryptedMsg:string
test('encrypt something with the shared key', async t => {
    eccEncryptedMsg = await aesEncrypt('hello ECC', sharedKey)
    t.equal(typeof eccEncryptedMsg, 'string', 'should return a string by default')
})

test('alice and bob can decrypt the message', async t => {
    const sharedKey = await getSharedKey(eccKeypair.privateKey, BobsKeys.publicKey)
    const dec = await aesDecrypt(eccEncryptedMsg, sharedKey)
    t.equal(dec, 'hello ECC', 'can decrypt with a shared key')

    const alicesMessage = await eccDecrypt(
        eccEncryptedMsg,
        eccKeypair.privateKey,
        BobsKeys.publicKey
    )

    t.equal(alicesMessage, 'hello ECC',
        'Alice can decrypt by calling ecc.decrypt')

    const bobsMessage = await eccDecrypt(
        eccEncryptedMsg,
        BobsKeys.privateKey,
        eccKeypair.publicKey
    )

    t.equal(bobsMessage, 'hello ECC', 'Bob can decrypt by calling ecc.decrypt')
})

test('Can encrypt with ecc.encrypt', async t => {
    const encrypted = await eccEncrypt(
        'hello ecc',
        eccKeypair.privateKey,
        BobsKeys.publicKey
    )

    t.equal(typeof encrypted, 'string', 'should return a string')
    console.log('*encrypted**', encrypted)

    const decrypted = await eccDecrypt(
        encrypted,
        eccKeypair.privateKey,
        BobsKeys.publicKey
    )

    t.equal(decrypted, 'hello ecc', 'should decrypt to the right text')
})
