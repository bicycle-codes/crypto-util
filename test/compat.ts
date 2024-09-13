import { test } from '@bicycle-codes/tapzero'
import { create } from '../src/compat/aes'

test('create a new AES key', t => {
    const newKey = create()
    t.ok(newKey, 'should retunr a new key')
})
