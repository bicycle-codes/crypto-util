import { test } from '@bicycle-codes/tapzero'
import {
    create as createAes,
    decrypt as aesDecrypt,
    encrypt as aesEncrypt,
} from '../src/noble/aes'
import {
    create as createEcc,
    sign as eccSign,
    verify as eccVerify,
    type Keypair,
    exportPublicKey,
    publicKeyToDid,
    didToPublicKey,
    encrypt as eccEncrypt
} from '../src/noble/ecc'
import type { DID } from '../src/types'
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
let aliceEncKeys:Keypair
let aliceSignKeys:Keypair
test('create an ECC keypair', async t => {
    aliceEncKeys = await createEcc()
    aliceSignKeys = await createEcc()
    t.ok(aliceEncKeys.privateKey, 'should return a new keypair')
    t.ok(aliceSignKeys.privateKey, 'should return a new keypair')
})

let sig:string
test('use the keys to sign something', async t => {
    sig = await eccSign('hello ecc', aliceSignKeys.privateKey)
    t.equal(typeof sig, 'string', 'should return a string by default')

    const sigArray = await eccSign('hello ecc', aliceSignKeys.privateKey, {
        format: 'raw'
    })

    t.ok(sigArray instanceof Uint8Array, 'can return a Uint8Array')
})

test('export public key', t => {
    const asString = exportPublicKey(aliceSignKeys)
    t.equal(typeof asString, 'string', 'should return a string')
})

let did:DID
test('transform the public key into a DID string', t => {
    did = publicKeyToDid(aliceSignKeys)
    t.equal(did.length, 56, 'should be 56 characters long')
    t.equal(typeof did, 'string', 'should return a string')
    t.ok(did.startsWith('did:key:z'), 'should be DID format')
})

test('transform the DID string to a public key', t => {
    const publicKey = didToPublicKey(did)
    t.equal(publicKey.type, 'ed25519', 'should return the right `type`')
})

test('verify the signature with a Uint8Array public key', async t => {
    const isOk = await eccVerify('hello ecc', sig, aliceSignKeys.publicKey)
    t.ok(isOk, 'should verify a valid signature')
})

test('verify the signature with a DID format public key', async t => {
    const isOk = await eccVerify('hello ecc', sig, did)
    t.ok(isOk, 'should verify a valid signature')
})

let bobEncKeys:Keypair
test('ecnrypt something with ECC', async t => {
    bobEncKeys = await createEcc()

    const encrypted = await 
})
