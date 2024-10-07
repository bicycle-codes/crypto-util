# notes

## [derive a key from existing random material](https://github.com/paulmillr/noble-curves/discussions/122#discussioncomment-8593465)

```js
import { sha512 } from '@noble/hashes/sha512'
import { x25519 } from '@noble/curves/x25519'
import { randomBytes } from '@noble/ciphers/webcrypto'

function generateSeed () {
    let seed = new Uint8Array(32)
    crypto.getRandomValues(seed)
    return seed
}

function x25519Keygen (seed = generateSeed()) {
   let sk = sha512(seed)
   let pk = x25519.scalarMultBase(sk)
   return { sk, pk }
}
```

## [simple "hybrid" encryption](https://github.com/paulmillr/noble-ciphers/discussions/32#discussioncomment-8594330)

```js
import { hkdf } from '@noble/hashes/hkdf'
import { xchacha20poly1305 } from '@noble/ciphers/chacha'
import { randomBytes } from '@noble/ciphers/webcrypto'

const sharedKey = hkdf(
    x25519.getSharedSecret(privA, pubB),
    undefined,
    'my-app',
    32
)
const nonce = randomBytes(32);
const cipher = xchacha20poly1305(sharedKey, nonce); // or xsalsa
cipher.encrypt(data);
```
