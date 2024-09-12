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

## install

```sh
npm i -S @bicycle-codes/crypto-util
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
