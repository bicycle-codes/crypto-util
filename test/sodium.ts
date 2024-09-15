import { test } from '@bicycle-codes/tapzero'
import { didToPublicKey, fromString } from '../src'
import {
    create,
    sign,
    verify,
    stringify,
    encrypt,
    decrypt,
    importPublicKey,
    publicKeyToDid
} from '../src/sodium/ecc'
import {
    create as createAes,
    encrypt as encryptAes,
    decrypt as decryptAes
} from '../src/sodium/aes'
import type { DID } from '../src/types'
import type { LockKey } from '../src'

test('', t => {
    t.comment('-----------ECC tests-----------')
})

let alicesKeys:LockKey
test('create a keypair', async t => {
    const keys = alicesKeys = await create()
    t.ok(keys.privateKey, 'should return some keys')
})

test('sign something, return Uint8Array', async t => {
    const sig = await sign('hello sodium', alicesKeys, { format: 'raw' })
    t.ok(sig instanceof Uint8Array,
        'should return the signature as a Uint8Array')
    const isOk = await verify('hello sodium', sig, {
        publicKey: alicesKeys.publicKey
    })
    t.ok(isOk, 'should verify a valid signature')
})

let did:DID
test('transform the public key into a DID', async t => {
    const pubKey = did = await publicKeyToDid(alicesKeys.publicKey)
    t.ok(pubKey.startsWith('did:key:z'))
})

test('transform the did to a public key', t => {
    const pubKey = didToPublicKey(did)
    t.ok(pubKey.publicKey instanceof Uint8Array, 'should return a Uint8Array')
    t.equal(pubKey.type, 'ed25519', 'should have the correct key type')
})

let sig:string
test('sign something', async t => {
    sig = await sign('hello sodium', alicesKeys)
    t.equal(typeof sig, 'string', 'should return a string by default')
})

test('verify a signature', async t => {
    const isOk = await verify('hello sodium', fromString(sig), {
        publicKey: alicesKeys.publicKey
    })
    t.equal(isOk, true, 'should verify a valid signature')
})

let keyString:string
test('serialize the public key', (t) => {
    keyString = stringify(alicesKeys)
    t.equal(typeof keyString, 'string', 'should return a string')
})

test('deserialize the public key', t => {
    const key = importPublicKey(keyString)
    t.ok(key instanceof Uint8Array)
})

test('verify a signature given a string public key', async (t) => {
    const isOk = await verify('hello sodium', sig, {
        publicKey: keyString
    })
    t.ok(isOk, 'Can verify given a string as public key')
})

test('verify an invalid signature', async t => {
    const isOk = await verify('hello bad signature', sig, {
        publicKey: keyString
    })
    t.equal(isOk, false, 'should not verify an invalid signature')
})

let encrypted:string
test('encrypt something', async t => {
    encrypted = await encrypt('hello encryption', alicesKeys)
    t.equal(typeof encrypted, 'string', 'should return a string by default')
})

test('decrypt', async t => {
    const decrypted = await decrypt(encrypted, alicesKeys, {
        outputFormat: 'utf8'
    })
    t.equal(decrypted, 'hello encryption', 'should decrypt the string')

    const decrypted2 = await decrypt(encrypted, alicesKeys)
    t.equal(decrypted2, 'hello encryption', 'should return a string by default')

    const decrypted3 = await decrypt(encrypted, alicesKeys, {
        outputFormat: 'raw'
    })
    t.ok(decrypted3 instanceof Uint8Array, 'can return a Uint8Array')
})

test('', t => {
    t.comment('-----------AES tests-----------')
})

let aesKey:string
test('create an AES key', async t => {
    const newKey = aesKey = await createAes()
    t.equal(typeof newKey, 'string', 'should return a string by default')
    const arrKey = await createAes({ format: 'raw' })
    t.ok(arrKey instanceof Uint8Array, 'Can return a Uint8Array')
})

let encryptedAes:string
test('encrypt with sodium + AES', async t => {
    encryptedAes = await encryptAes('hello sodium + AES', aesKey)
    t.equal(typeof encryptedAes, 'string', 'should return a string by default')
})

test('decrypt an AES encrypted string with sodium', async t => {
    const decrypted = await decryptAes(encryptedAes, aesKey)
    t.equal(typeof decrypted, 'string', 'should return a string by default')
    t.equal(decrypted, 'hello sodium + AES', 'should decrypt to the right text')
})
