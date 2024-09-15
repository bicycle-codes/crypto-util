import { test } from '@bicycle-codes/tapzero'
import { toString } from 'uint8arrays'
import {
    create as createAes,
    exportKey as exportAesKey,
    encrypt as aesEncrypt,
    decrypt as aesDecrypt
} from '../src/aes/webcrypto.js'
import {
    create as createEcc,
    sign as eccSign,
    verify as eccVerify,
    getSharedKey,
    decrypt as eccDecrypt,
    encrypt as eccEncrypt,
    exportPublicKey as eccExportKey,
    publicKeyToDid as eccPublicToDid,
    importDid,
    verifyWithDid as eccVerifyWithDid
} from '../src/ecc/webcrypto.js'
import {
    create as createRsa,
    sign as rsaSign,
    verify as rsaVerify,
    encrypt as rsaEncrypt,
    decrypt as rsaDecrypt,
    exportKey as exportRsaKey,
    publicKeyToDid as rsaPublicKeyToDid,
    didToPublicKey as rsaDidToPublicKey,
    importDid as rsaImportDid,
    verifyWithDid as rsaVerifyWithDid
} from '../src/rsa/webcrypto.js'
import {
    arrBufToBase64,
    isCryptoKeyPair,
    didToPublicKey,
} from '../src/index.js'
import { KeyUse, type DID } from '../src/types.js'

// ---------------------------------------------------
// AES
// ---------------------------------------------------
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

// ---------------------------------------------------
// RSA
// ---------------------------------------------------
let rsaKeypair:CryptoKeyPair
test('Create an RSA keypair', async t => {
    const keys = rsaKeypair = await createRsa(KeyUse.Sign)
    t.ok(keys.privateKey instanceof CryptoKey, 'should create a new keypair')
    t.ok(keys.publicKey instanceof CryptoKey, 'should create a new keypair')
})

let rsaDid:DID
test('RSA public key to DID', async t => {
    const arr = await exportRsaKey(rsaKeypair.publicKey)
    const did = rsaDid = await rsaPublicKeyToDid(arr)
    t.equal(did.length, 415, 'RSA did should be 415 characters')
    t.equal(typeof did, 'string', 'should return a string')
    t.ok(did.startsWith('did:key:z'), 'should return the right format DID')
})

test('RSA did to public key', t => {
    const key = rsaDidToPublicKey(rsaDid)
    t.ok(key.publicKey instanceof Uint8Array, 'should return a Uint8Array')
    t.equal(key.type, 'rsa', 'should return the key type')
})

test('Use the public key from the DID to verify a signature', async t => {
    const key = await rsaImportDid(rsaDid)
    const sig = await rsaSign('hello dids', rsaKeypair.privateKey)
    const isOk = await rsaVerify('hello dids', sig, key)
    t.ok(isOk, 'should verify a valid signature')
})

test('rsa.verifyWithDid', async t => {
    const sig = await rsaSign('hello dids', rsaKeypair.privateKey)
    const sigString = arrBufToBase64(sig)
    const isOk = await rsaVerifyWithDid('hello dids', sigString, rsaDid)
    t.ok(isOk, 'should verify a valid string with the DID')
})

test('Export the public key as a string', async t => {
    const str = await exportRsaKey(rsaKeypair.publicKey, { format: 'string' })
    t.equal(typeof str, 'string', 'should retunr a base64 string')
})

// RSA sign things
test('sign things with RSA', async t => {
    const sig = await rsaSign('hello RSA', rsaKeypair.privateKey)
    const sigString = arrBufToBase64(sig)
    t.ok(sig, 'should return a signature')
    t.equal(sigString.length, 344, 'signature should be 344 characters')
    t.equal(typeof sigString, 'string', 'should convert to a string')
})

// RSA encrypt things
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

// ---------------------------------------------------
// ECC
// ---------------------------------------------------
let eccKeypair:CryptoKeyPair
let eccSignKeys:CryptoKeyPair
test('create an ECC keypair', async t => {
    eccKeypair = await createEcc(KeyUse.Encrypt)
    eccSignKeys = await createEcc(KeyUse.Sign)
    t.ok(isCryptoKeyPair(eccKeypair), 'should return a new keypair')
})

test('export the public key', async t => {
    const publicKey = await eccExportKey(eccKeypair.publicKey)
    t.ok(publicKey instanceof Uint8Array,
        'should retunr a Uint8Array by default')
    const keyStirng = await eccExportKey(eccKeypair.publicKey, {
        format: 'string'
    })
    t.equal(typeof keyStirng, 'string', 'should return a string given opts')
})

let eccDid:DID
test('ECC public key to DID', async t => {
    const arr = await eccExportKey(eccSignKeys.publicKey)
    const did = eccDid = await eccPublicToDid(arr)
    t.equal(did.length, 101, 'ECC did should be 101 characters long')
    t.equal(typeof did, 'string', 'should return a string')
    t.ok(did.startsWith('did:key:z'), 'should return the right format DID')
})

test('ECC public key to DID, pass a CryptoKey instance', async t => {
    const did = await eccPublicToDid(eccSignKeys.publicKey)
    t.ok(did.startsWith('did:key:z'), 'should return the right format DID')
})

test('ECC DID to public key', t => {
    const key = didToPublicKey(eccDid)
    t.ok(key.publicKey instanceof Uint8Array, 'returns the public key as Uint8Array')
    t.equal(key.type, 'ed25519', 'should return the key type')
})

test('Use the public key from the DID to verify something', async t => {
    const sig = await eccSign('hello dids', eccSignKeys.privateKey)
    const key = await importDid(eccDid)
    const isOk = await eccVerify('hello dids', sig, key)
    t.ok(isOk, 'should verify a valid signature')
})

test('ecc.verifyWithDid', async t => {
    const sig = await eccSign('hello dids', eccSignKeys.privateKey)
    const isOk = await eccVerifyWithDid('hello dids', sig, eccDid)
    t.ok(isOk, 'should verify a valid signature')
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

let eccEncryptedText:string
test('Can encrypt with ecc.encrypt', async t => {
    eccEncryptedText = await eccEncrypt(
        'hello ecc',
        eccKeypair.privateKey,
        BobsKeys.publicKey
    )

    t.equal(typeof eccEncryptedText, 'string',
        'should return a string by default')
})

test('Can decrypt with ecc.decrypt', async t => {
    const decrypted = await eccDecrypt(
        eccEncryptedText,
        eccKeypair.privateKey,
        BobsKeys.publicKey
    )

    t.equal(decrypted, 'hello ecc', 'should decrypt to the right text')

    const bobsDecrypted = await eccDecrypt(
        eccEncryptedText,
        BobsKeys.privateKey,
        eccKeypair.publicKey
    )

    t.equal(bobsDecrypted, 'hello ecc', 'bob can decrypt it too')
})

// ---------------------------------------------------
// Misc
// ---------------------------------------------------

test('Generic DID to public key', t => {
    const key = didToPublicKey(eccDid)

    t.equal(key.type, 'ed25519',
        'should return the correct key type -- ed25519')

    t.equal(didToPublicKey(rsaDid).type, 'rsa',
        'should return the correct key type -- rsa')
})
