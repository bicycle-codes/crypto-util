import { test } from '@bicycle-codes/tapzero'
import {
    create as createAes,
    decrypt as aesDecrypt,
    encrypt as aesEncrypt,
} from '../src/noble/aes'
import {
    create as createEcc,
    sign as eccSign,
    type Keypair,
    exportPublicKey,
    publicKeyToDid
} from '../src/noble/ecc'
import type { Cipher } from '../src/noble'

// ---------------------------------------------------
// AES
// ---------------------------------------------------

let key:Cipher
test('create a new AES key', t => {
    const newKey = key = createAes()
    t.ok(newKey, 'should return a new key')
    t.ok(newKey.decrypt, 'should return a new key')
    t.ok(newKey.encrypt, 'should return a new key')
})

let aesEncryptedText:string
test('encrypt some text with AES', async t => {
    aesEncryptedText = await aesEncrypt('hello AES', key)
    t.equal(typeof aesEncryptedText, 'string', 'should return a string')
})

test('decrypt the text with AES', async t => {
    const decrypted = await aesDecrypt(aesEncryptedText, key)
    t.equal(decrypted, 'hello AES', 'should decrypt to the right text')
})

// ---------------------------------------------------
// ECC
// ---------------------------------------------------
let encKeys:Keypair
let signKeys:Keypair
test('create an ECC keypair', async t => {
    encKeys = await createEcc()
    signKeys = await createEcc()
    t.ok(encKeys.privateKey, 'should return a new keypair')
    t.ok(signKeys.privateKey, 'should return a new keypair')
})

test('use the keys to sign something', t => {
    const sig = eccSign('hello ecc', signKeys.privateKey)
    t.equal(typeof sig, 'string', 'should return a string by default')
})

test('export public key', t => {
    const asString = exportPublicKey(signKeys)
    t.equal(typeof asString, 'string', 'should return a string')
})

test('transform the public key into a DID string', t => {
    const did = publicKeyToDid(signKeys)
    t.equal(typeof did, 'string', 'should return a string')
    t.ok(did.startsWith('did:key:z'), 'should be DID format')
})

// test('verify the signature', async t => {

// })
