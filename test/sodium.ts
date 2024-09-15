import { test } from '@bicycle-codes/tapzero'
import { fromString } from '../src'
import {
    create,
    sign,
    verify,
    stringify,
    encrypt,
    decrypt,
    importPublicKey
} from '../src/sodium/ecc'
import type { LockKey } from '../src'
// import Debug from '@bicycle-codes/debug/node'
// const debug = Debug()

let alicesKeys:LockKey
test('create a keypair', async t => {
    const keys = alicesKeys = await create()
    t.ok(keys.privateKey, 'should return some keys')
})

test('sign something, return Uint8Array', async t => {
    const sig = await sign('hello sodium', alicesKeys, { outputFormat: 'raw' })
    t.ok(sig instanceof Uint8Array,
        'should return the signature as a Uint8Array')
    const isOk = await verify('hello sodium', sig, {
        publicKey: alicesKeys.publicKey
    })
    t.ok(isOk, 'should verify a valid signature')
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
