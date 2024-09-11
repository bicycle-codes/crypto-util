import { test } from '@bicycle-codes/tapzero'
import { create as createAes } from '../src/aes.js'
import { create as createRsa } from '../src/rsa.js'
import {
    DEFAULT_HASH_ALGORITHM,
    DEFAULT_RSA_SIZE
} from '../src/constants.js'
import { KeyUse } from '../src/types.js'

test('Create an AES key', async t => {
    const aesKey = await createAes()
    t.ok(aesKey instanceof CryptoKey, 'Should return a CryptoKey')
})

test('Create an RSA keypair', async t => {
    const keys = await createRsa(
        DEFAULT_RSA_SIZE,
        DEFAULT_HASH_ALGORITHM,
        KeyUse.Sign
    )

    t.ok(keys.privateKey instanceof CryptoKey, 'should create a new keypair')
    t.ok(keys.publicKey instanceof CryptoKey, 'should create a new keypair')
})
