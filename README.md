# crypto util
![tests](https://github.com/bicycle-codes/crypto-util/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/crypto-util?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://flat.badgen.net/packagephobia/install/@bicycle-codes/crypto-util)](https://packagephobia.com/result?p=@bicycle-codes/crypto-util)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

Utility functions for working with crypto keys in the browser or node.

[See the docs](https://bicycle-codes.github.io/crypto-util/)

## Contents

<!-- toc -->

- [install](#install)
- [example](#example)
  * [Create a new keypair](#create-a-new-keypair)
  * [Use 2 ECC keypairs to create a new AES key](#use-2-ecc-keypairs-to-create-a-new-aes-key)
  * [Encrypt a message with an AES key](#encrypt-a-message-with-an-aes-key)
  * [Decrypt with AES keys](#decrypt-with-aes-keys)
  * [encrypt with ECC keys](#encrypt-with-ecc-keys)
  * [Decrypt with ECC keys](#decrypt-with-ecc-keys)
  * [Sign things](#sign-things)
  * [Verify a signature](#verify-a-signature)
- [API](#api)
  * [ESM](#esm)
  * [Common JS](#common-js)
- [use](#use)
  * [JS](#js)
  * [pre-built JS](#pre-built-js)

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
import { create } from '@bicycle-codes/crypto-util'

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

### Encrypt a message with an AES key
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
import '@bicycle-codes/key-utils'
```

### Common JS
```js
require('@bicycle-codes/key-utils/module')
```

## use

### JS
```js
import '@bicycle-codes/crypto-util'
```

### web crypto vs sodium
To use the [webcrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API), import from the `webcrypto` sub-path.

```js
import { aes, ecc, rsa } from '@bicycle-codes/crypto-util/webcrypto'
```

### pre-built JS
This package exposes minified, pre-bundled JS files too. Copy them to a location
that is accessible to your web server, then link in HTML.

#### copy
```sh
cp ./node_modules/@namespace/package/dist/index.min.js ./public/crypto-util
```

#### HTML
```html
<script type="module" src="./crypto-util.min.js"></script>
```
