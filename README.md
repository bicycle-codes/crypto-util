# crypto util
![tests](https://github.com/bicycle-codes/crypto-util/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/crypto-util?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://flat.badgen.net/packagephobia/install/@bicycle-codes/crypto-util)](https://packagephobia.com/result?p=@bicycle-codes/crypto-util)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

Utility functions for working with crypto keys in the browser or node.

This is some helpful functions that make it easier to work with cryptography. Note this does *not* deal with storing keys. Look at using [@bicycle-codes/webauthn-keys](https://github.com/bicycle-codes/webauthn-keys/) (biometric authentication) or [indexedDB](https://github.com/jakearchibald/idb-keyval) for help with that.

This includes both [sodium](https://github.com/jedisct1/libsodium.js) based keys and also [webcrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) functions.

The Webcrypto keys are preferable because we create them as
[non-extractable](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey#extractable) keys, and are able to persist them in indexedDB, despite not being able to read the private key.

> [!TIP]
> Request "persistent" storage with the [`.persist()`](https://developer.mozilla.org/en-US/docs/Web/API/StorageManager/persist) method in the browser.

The install size is kind of large (9.77 MB) because this includes a minified bundle of the [sodium library](https://github.com/jedisct1/libsodium.js).

> [!TIP]
> [See the docs generated from typescript](https://bicycle-codes.github.io/crypto-util/)

## Contents

<!-- toc -->

- [install](#install)
- [example](#example)
  * [Create a new keypair](#create-a-new-keypair)
  * [Use 2 ECC keypairs to create a new AES key](#use-2-ecc-keypairs-to-create-a-new-aes-key)
  * [Encrypt with AES keys](#encrypt-with-aes-keys)
  * [Decrypt with AES keys](#decrypt-with-aes-keys)
  * [encrypt with ECC keys](#encrypt-with-ecc-keys)
  * [Decrypt with ECC keys](#decrypt-with-ecc-keys)
  * [Sign things](#sign-things)
  * [Verify a signature](#verify-a-signature)
- [API](#api)
  * [ESM](#esm)
  * [Common JS](#common-js)
  * [pre-built JS](#pre-built-js)
  * [webcrypto vs sodium](#webcrypto-vs-sodium)
- [webcrypto API](#webcrypto-api)
  * [example](#example-1)
- [webcrypto AES API](#webcrypto-aes-api)
  * [`aes.create`](#aescreate)
  * [`aes.encrypt`](#aesencrypt)
  * [`aes.decrypt`](#aesdecrypt)
- [webcrypto ECC API](#webcrypto-ecc-api)
  * [`ecc.create`](#ecccreate)
  * [`sign`](#sign)
  * [`verifyWithDid`](#verifywithdid)
  * [`getSharedKey`](#getsharedkey)
  * [`encrypt`](#encrypt)
  * [`decrypt`](#decrypt)
- [sodium API](#sodium-api)
- [Sodium AES API](#sodium-aes-api)
  * [Sodium + AES example](#sodium--aes-example)
  * [`aes.create`](#aescreate-1)
  * [`aes.encrypt`](#aesencrypt-1)
  * [`aes.decrypt`](#aesdecrypt-1)
- [Sodium ECC API](#sodium-ecc-api)
  * [Sodium + ECC example](#sodium--ecc-example)
  * [`ecc.create`](#ecccreate-1)
  * [`ecc.sign`](#eccsign)
  * [`ecc.publicKeyToDid`](#eccpublickeytodid)
  * [`ecc.verify`](#eccverify)
  * [`ecc.verifyWithDid`](#eccverifywithdid)
  * [`ecc.encrypt`](#eccencrypt)
  * [`ecc.decrypt`](#eccdecrypt)
- [see also](#see-also)

<!-- tocstop -->

--------------------------------------------------------------
## install
--------------------------------------------------------------

```sh
npm i -S @bicycle-codes/crypto-util
```

--------------------------------------------------------------
## example
--------------------------------------------------------------

### Create a new keypair
Use ECC keys with the [web crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

Also, you can use [RSA keys](./test/index.ts#L62).

```js
import { create, KeyUse } from '@bicycle-codes/crypto-util'

// create a new keypair
const encryptKeypair = await create(KeyUse.Encrypt)
const signKeys = await create(KeyUse.Sign)
```

### Use 2 ECC keypairs to create a new AES key
This requires a keypair + another keypair to derive a shared AES key.

```js
import { getSharedKey } from '@bicycle-codes/crypto-util/ecc'
import { KeyUse } from '@bicycle-codes/crypto-util/types'

const alicesKeys = await createEcc(KeyUse.Encrypt)
const bobsKeys = await createEcc(KeyUse.Encrypt)

// pass in our private key, their public key
const sharedKey = await getSharedKey(alicesKeys.privateKey, bobsKeys.publicKey)
```

Bob can derive the same key by using their private key + Alice's public key.

```js
const bobsSharedKey = await getSharedKey(bobsKeys.privateKey, alicesKeys.publicKey)
```

### Encrypt with AES keys
Encrypt a given message with a given key.

```js
import { create, encrypt } from '@bicycle-codes/crypto-util/aes'

const aesKey = await create()
const aesEncryptedText = await encrypt('hello AES', aesKey)
```

### Decrypt with AES keys

```js
import { decrypt } from '@bicycle-codes/crypto-util/aes'

const decrypted = await decrypt(aesEncryptedText, aesKey)
```

### encrypt with ECC keys
This is a message from Alice to Bob. We use Alice's private key & Bob's
public key.

```js
import {
  KeyUse,
  create,
  encrypt,
  decrypt
} from '@bicycle-codes/crypto-util'

const alicesKeys = await create(KeyUse.Encrypt)
const bobsKeys = await create(KeyUse.Encrypt)
const eccEncryptedText = await encrypt(
    'hello ecc',
    alicesKeys.privateKey,
    bobsKeys.publicKey
)
```

### Decrypt with ECC keys
Bob can decrypt the message encrypted by Alice, because we used bob's public
key when encrypting it.

```js
// note keys are reversed here --
// alice's public key and bob's private key
const decrypted = await decrypt(
    eccEncryptedText,
    bobsKeys.privateKey,
    alicesKeys.publicKey
)

// => 'hello ecc'
```

### Sign things
Create another keypair that is used for signatures.

```js
import { KeyUse } from '@bicycle-codes/crypto-util'

const eccSignKeys = await createEcc(KeyUse.Sign)
```

#### Create signatures

```js
import { sign } from '@bicycle-codes/crypto-util/ecc'

const sig = await sign('hello dids', eccSignKeys.privateKey)
```

#### Create a DID
A DID is a [decentralized identifier](https://github.com/w3c/did-wg/blob/main/did-explainer.md), a string the encodes a user's public key.

If you are transmiting your public key along with a message, for example, this is the preferred format.

```js
import { publicKeyToDid } from '@bicycle-codes/crypto-util'

const did = await publicKeyToDid(eccSignKeys.publicKey)
```

### Verify a signature
Use a DID to verify a signature string.

```js
import { verifyWithDid, sign } from '@bicycle-codes/crypto-util/ecc'

const sig = await sign('hello dids', eccSignKeys.privateKey)
const isOk = await verifyWithDid('hello dids', sig, did)
```


--------------------------------------------------------------
## API
--------------------------------------------------------------

[See the API docs](https://bicycle-codes.github.io/crypto-util/)

This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import * as util from '@bicycle-codes/crypto-utils'
```

### Common JS
```js
const util = require('@bicycle-codes/crypto-utils')
```

### pre-built JS
This package exposes minified, pre-bundled JS files too. Copy them to a location
that is accessible to your web server, then link in HTML.

#### copy
```sh
cp ./node_modules/@bicycle-codes/crypto-util/dist/index.min.js ./public/crypto-util.js
```

#### HTML
```html
<script type="module" src="./crypto-util.js"></script>
```

### webcrypto vs sodium

To use the [webcrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), import from the `webcrypto` sub-path.


-----------------------------------------------------------
## webcrypto API
-----------------------------------------------------------
This depends on an environment with a [webcrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

```js
import { aes, ecc, rsa } from '@bicycle-codes/crypto-util/webcrypto'
```

### example
```js
import { rsa, ecc, aes } from '@bicycle-codes/crypto-util/webcrypto'

// create some ECC keypairs
const eccKeypair = await ecc.create(KeyUse.Sign)
const eccSignKeys = await ecc.create(KeyUse.Encrypt)

// get the public key as a string
const publicKey = await ecc.exportPublicKey(eccSignKeys.publicKey)

// get the public key as a DID format string
const did = await ecc.publicKeyToDid(eccSignKeys.publicKey)

// transform a DID string to a public key instance
const publicKey = ecc.didToPublicKey(eccDid)
```

-----------------------------------------------------------
## webcrypto AES API
-----------------------------------------------------------
### `aes.create`
Create a new AES-GCM key.

```ts
function create (opts:{ alg, length } = {
    alg: DEFAULT_SYMM_ALGORITHM,
    length: DEFAULT_SYMM_LEN
}):Promise<CryptoKey>
```

#### `aes.create` example

```js
import { create } from '@bicycle-codes/crypto-util/webcrypto/aes'

const aesKey = await createAes()
```

### `aes.encrypt`
Encrypt a string.

```ts
async function encrypt (
    msg:Msg,
    key:SymmKey|string,
    opts?:Partial<SymmKeyOpts>
):Promise<string>
```

```js
import { encrypt } from '@bicycle-codes/crypto-util/webcrypto/aes'

let aesEncryptedText:string
test('encrypt some text with AES', async t => {
    aesEncryptedText = await encrypt('hello AES', aesKey)
    // returns a string by default
})
```

### `aes.decrypt`
```ts
async function decrypt (
    msg:Msg,
    key:SymmKey|string,
    opts?:Partial<SymmKeyOpts>,
    charSize:CharSize = DEFAULT_CHAR_SIZE
):Promise<string>
```

```js
import { decrypt } from '@bicycle-codes/crypto-util/webcrypto/aes'

const decrypted = await decrypt(aesEncryptedText, aesKey)
// => 'hello AES'
```

-----------------------------------------------------------
## webcrypto RSA API
-----------------------------------------------------------
We expose RSA because not all browser yet support ECC keys. See [src/rsa/webcrypto.ts](./src/rsa/webcrypto.ts) and [test/index.ts](test/index.ts#L60).


-----------------------------------------------------------
## webcrypto ECC API
-----------------------------------------------------------

### `ecc.create`
```ts
async function create (
    use:KeyUse,
    curve:EccCurve = EccCurve.P_256,
):Promise<CryptoKeyPair>
```

#### `create` example

```js
import { create } from '@bicycle-codes/crypto-util/webcrypto/ecc'

const alicesEncryptionKeys = await createEcc(KeyUse.Encrypt)
const alicesSigningKeys = await createEcc(KeyUse.Sign)
```


### `sign`
```ts
async function sign (
    msg:Msg,  // <-- string or Uint8Array
    privateKey:PrivateKey,
    { format }:{ format: 'base64'|'raw' } = { format: 'base64' },
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    hashAlg:HashAlg = DEFAULT_HASH_ALGORITHM,
):Promise<ArrayBuffer|string>
```

#### example

```js
import { sign } from '@bicycle-codes/crypto-util/webcrypto/ecc'

const sig = await sign('hello webcrypto', eccSignKeys.privateKey)
```

### `verifyWithDid`
Verify a signature with a DID format string.

```ts
async function verifyWithDid (
    msg:string,
    sig:string,
    did:DID
):Promise<boolean>
```

```js
import { verifyWithDid } from '@bicycle-codes/crypto-util/webcrypto/ecc'

const isOk = await verifyWithDid('hello dids', sig, did)
```

### `getSharedKey`
Get a shared key given two existing keypairs.

```ts
async function getSharedKey (
    privateKey:PrivateKey,
    publicKey:PublicKey,
    opts?:Partial<{
        alg:'AES-GCM'|'AES-CBC'|'AES-CTR'
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<SymmKey>
```

```js
let BobsKeys:CryptoKeyPair
let sharedKey:CryptoKey

const BobsKeys = await createEcc(KeyUse.Encrypt)
const sharedKey = await getSharedKey(eccKeypair.privateKey, BobsKeys.publicKey)
t.ok(sharedKey instanceof CryptoKey, 'should return a `CryptoKey`')
```

### `encrypt`
Encrypt something with your private key and the recipient's public key.

```ts
async function encrypt (
    msg:Msg,  // <-- string or Uint8Array
    privateKey:PrivateKey,
    publicKey:string|PublicKey,  // <-- base64 or key
    { format }:{ format: 'base64'|'raw' } = { format: 'base64' },
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<{
        alg:SymmAlg
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<Uint8Array|string>
```

#### example

```js
const eccEncryptedText = await ecc.encrypt(
    'hello ecc',
    alicesKeys.privateKey,
    BobsKeys.publicKey
)
```

### `decrypt`
Decrypt some text that was encrypted with `ecc.ecncrypt`.

```ts
async function decrypt (
    msg:Msg,  // <-- string or Uint8Array
    privateKey:PrivateKey,
    publicKey:string|PublicKey,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<{
        alg:'AES-GCM'|'AES-CBC'|'AES-CTR'
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<string>
```

#### example
Note the keys a swapped here -- the public and private keys can come from either
keypair and it still works.

```js
const decrypted = await ecc.decrypt(
    eccEncryptedText,
    BobsKeys.privateKey,
    alicesKeys.publicKey
)
```

-----------------------------------------------------------
## sodium API
-----------------------------------------------------------
These should work anywhere that JS can run.

```js
import { aes, ecc, rsa } from '@bicycle-codes/crypto-util/sodium'
```

Or import individual modules
```js
import * as aes from '@bicycle-codes/crypto-util/sodium/aes'
import * as ecc from '@bicycle-codes/crypto-util/sodium/ecc'
import * as webcryptoAes from '@bicycle-codes/crypto-util/webcrypto/aes'
```

-----------------------------------------------------------
## Sodium AES API
-----------------------------------------------------------
Encrypt with [AEGIS-256](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aegis-256) (symmetric crypto).


### Sodium + AES example
```js
import {
    create,
    encrypt,
    decrypt
} from '@bicycle-codes/crypto-util/sodium/aes'

// create a new key
const key = await create()

// or create a key, return a Uint8Array
const keyAsBuffer = await createAes({ format: 'raw' })

// encrypt something
const encryptedString = await encrypt('hello sodium + AES', key)
```

### `aes.create`
Create a new AES key. Pass `{ format: 'raw' }` to return a `Uint8Array`.

```ts
async function create (opts:{
    format: 'string'|'raw'
} = { format: 'string' }):Promise<Uint8Array|string>
```

#### example
```js
import { create } from '@bicycle-codes/crypto-util/sodium/aes'

const aesKey = await create()
```

### `aes.encrypt`
Encrypt the given string or buffer. Pass `{ format: 'raw' }` to return a `Uint8Array`.

```ts
async function encrypt (
    msg:Uint8Array|string,
    key:Uint8Array|string,
    opts:Partial<{
        iv?:Uint8Array
        format?:'string'|'raw'
    }> = { format: 'string' },
):Promise<Uint8Array|string>
```

#### example
```js
import { encrypt } from '@bicycle-codes/crypto-util/sodium/aes'

const encryptedString = await encryptAes('hello sodium + AES', aesKey)
```

### `aes.decrypt`
Decrypt the given string or buffer. Pass `{ format: 'raw' }` to return a `Uint8Array`.

```ts
async function decrypt (
    cipherText:string|Uint8Array,
    key:string|Uint8Array,
    opts:{ format:'string'|'raw' } = { format: 'string' }
):Promise<Uint8Array|string>
```

#### example

```ts
import { decrypt } from '@bicycle-codes/sodium/aes'

const decrypted = await decrypt(encryptedAes, aesKey)
// => "hello sodium + AES"
```

-----------------------------------------------------------
## Sodium ECC API
-----------------------------------------------------------

### Sodium + ECC example
```js
import * as ecc from '@bicycle-codes/crypto-util/sodium/ecc'

const keys = await ecc.create()
```

### `ecc.create`

Create a new Edward keypair.
```ts
async function create (
    use:KeyUse,
    curve:EccCurve = EccCurve.P_256,
):Promise<CryptoKeyPair>
```

#### `.create` example

```js
import { create } from '@bicycle-codes/crypto-util/sodium/ecc'

const keys = await create()
```

### `ecc.sign`
Create a signature for the diven data. Pass `{ format: 'raw' }` to get a `Uint8Array` instead of a string.

```ts
async function sign (
    data:string|Uint8Array,
    key:LockKey,
    opts:{
        format:'string'|'raw'
    } = { format: 'string' }
):Promise<string|Uint8Array>
```

#### `ecc.sign` example
```js
import { sign } from '@bicycle-codes/crypto-util/webcrypto/ecc'

const sig = await sign('hello webcrypto', alicesKeys, { format: 'raw' })
```

### `ecc.publicKeyToDid`
Take a public key instance and return a DID format string.

```ts
async function publicKeyToDid (
    publicKey:Uint8Array|PublicKey
):Promise<DID>
```

#### `ecc.publicKeyToDid` example

```js
import {
  exportPublicKey,
  publicKeyToDid
} from '@bicycle-codes/crypto-util/webcrypto/ecc'

const arr = await exportPublicKey(eccSignKeys.publicKey)
const did = await publicKeyToDid(arr)
```

### `ecc.verify`
Verify the given signature + public key + message data.

```ts
async function verify (
    msg:Msg,  // <-- string or Uint8Array
    sig:string|Uint8Array|ArrayBuffer,
    publicKey:string|PublicKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    hashAlg: HashAlg = DEFAULT_HASH_ALGORITHM
):Promise<boolean>
```

#### `ecc.verify` example
```js
const key = await importDid(eccDid)
const isOk = await verify('hello webcrypto', sig, key)
t.ok(isOk, 'should verify a valid signature')
```

### `ecc.verifyWithDid`
Verify the given signature + message + public key are ok together, using the given DID string as public key material.

```ts
async function verifyWithDid (
    msg:string,
    sig:string,
    did:DID
):Promise<boolean>
```

#### `ecc.verifyWithDid` example

```js
import { verifyWithDid } from '@bicycle-codes/crypto-util/webcrypto/ecc'

const isOk = await verifyWithDid('hello dids', sig, did)
```

### `ecc.encrypt`

Use the given private and public keys to create a shared key, then encrypt the message with the key.

```ts
async function encrypt (
    msg:Msg,
    privateKey:PrivateKey,
    publicKey:string|PublicKey,  // <-- base64 or key
    { format }:{ format: 'base64'|'raw' } = { format: 'base64' },
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<{
        alg:SymmAlg
        length:SymmKeyLength
        iv:ArrayBuffer
    }>
):Promise<Uint8Array|string>
```

#### `ecc.encrypt example`

```js
import { encrypt } from '@bicycle-codes/crypto-util/webcrypto/ecc'

const eccEncryptedText = await encrypt(
    'hello ecc',
    AlicesKeys.privateKey,
    BobsKeys.publicKey
)
```

### `ecc.decrypt`
Decrypt a message given a public and private key. Note in the example, the keypairs are reversed from the `encrypt` example. This creates a new shared key via [Diffie Hellman](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey#key_agreement_algorithms).

```js
import { decrypt } from '@bicycle-codes/crypto-util/webcrypto/ecc'

const decrypted = await decrypt(
    eccEncryptedText,
    BobsKeys.privateKey,
    AlicesKeys.publicKey
)
```

## see also

* [[question] AES GCM — iv length #74](https://github.com/fission-codes/keystore-idb/issues/74) -- partial motivation for publishing this
* [`libsodium` docs](https://libsodium.gitbook.io/doc)
  - [AES256-GCM](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm)
  > Unless you absolutely need AES-GCM, use AEGIS-256 (crypto_aead_aegis256_*()) instead. It doesn’t have any of these limitations.
  - [AEGIS-256](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aegis-256)
* [Web Crypto API -- MDN docs](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
* [StorageManager: persist() method](https://developer.mozilla.org/en-US/docs/Web/API/StorageManager/persist)
* [idb-keyval](https://github.com/jakearchibald/idb-keyval) -- super simple key value storage API built on `indexedDB`.
