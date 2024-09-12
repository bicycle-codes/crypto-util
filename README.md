# key utils
![tests](https://github.com/bicycle-codes/crypto-util/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/icons?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://packagephobia.com/badge?p=@bicycle-codes/crypto-util)](https://packagephobia.com/result?p=@bicycle-codes/crypto-util)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

Utility functions for working with cryptography keys.

[See the docs](https://namespace.github.io/package-name/)

<!-- toc -->

- [install](#install)
- [API](#api)
  * [ESM](#esm)
  * [Common JS](#common-js)
- [CSS](#css)
  * [Import CSS](#import-css)
  * [Customize CSS via some variables](#customize-css-via-some-variables)
- [use](#use)
  * [JS](#js)
  * [pre-built JS](#pre-built-js)

<!-- tocstop -->

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

## CSS

### Import CSS

```js
import '@namespace/package-name/css'
```

Or minified:
```js
import '@namespace/package-name/css/min'
```

### Customize CSS via some variables

```css
component-name {
    --example: pink;
}
```

## use

`usage instructions here`

### JS
```js
import '@namespace/package/module'
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@namespace/package/dist/module.min.js ./public
```

#### HTML
```html
<script type="module" src="./module.min.js"></script>
```
