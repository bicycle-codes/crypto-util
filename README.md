# key utils
![tests](https://github.com/bicycle-codes/crypto-util/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/icons?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://flat.badgen.net/packagephobia/install/@bicycle-codes/crypto-util)](https://packagephobia.com/result?p=@bicycle-codes/crypto-util)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg?style=flat-square)](package.json)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

Utility functions for working with cryptography keys.

[See the docs](https://bicycle-codes.github.io/crypto-util/)

## Contents

<!-- toc -->

- [install](#install)
- [API](#api)
  * [ESM](#esm)
  * [Common JS](#common-js)
- [use](#use)
  * [JS](#js)
  * [pre-built JS](#pre-built-js)

<!-- tocstop -->

## install

```sh
npm i -S @bicycle-codes/crypto-util
```

## example

### Create a new keypair

Use ECC keys with the [web crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

```js
import { create } from '../src/ecc.js'

// create a new keypair
const encryptKeypair = await create(KeyUse.Encrypt)
const signKeys = await create(KeyUse.Sign)
```

### Use your keys to create a new AES key

This requires a keypair + another keypair to derive a shared AES key.

```js
import { getSharedKey } from '@bicycle-codes/crypto-util/ecc'
import { KeyUse } from '@bicycle-codes/crypto-util/types'

const bobsKeys = await createEcc(KeyUse.Encrypt)
// pass in our private key, their public key
const sharedKey = await getSharedKey(aliceKeys.privateKey, bobsKeys.publicKey)
```

Bob can derive the same key by using their private key + Alice's public key.

```js
const bobsSharedKey = await getSharedKey(bobsKey.privateKey, alicesKeys.publicKey)
```

### Encrypt a message with an AES key
This will create a new AES key and use it to encrypt the given message.

```js
import { decrypt } from '@bicycle-codes/crypto-util/ecc'

const alicesMessage = await decrypt(
    eccEncryptedMsg,
    alicesKeys.privateKey,
    bobsKeys.publicKey
)
```

## API

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
