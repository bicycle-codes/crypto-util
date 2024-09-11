import { test } from '@bicycle-codes/tapzero'
import { create } from '../src/aes.js'

test('pubic key to DID', async t => {
    const aesKey = await create()
    t.ok(aesKey instanceof CryptoKey, 'Should return a CryptoKey')
})
