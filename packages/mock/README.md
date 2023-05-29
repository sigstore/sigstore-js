# @sigstore/mock &middot; [![npm version](https://img.shields.io/npm/v/@sigstore/tuf.svg?style=flat)](https://www.npmjs.com/package/sigstore) [![CI Status](https://github.com/sigstore/sigstore-js/workflows/CI/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/ci.yml) [![Smoke Test Status](https://github.com/sigstore/sigstore-js/workflows/smoke-test/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/smoke-test.yml)

Mocking library for Sigstore service APIs.

## Features

* Mocked version of the Sigstore Fulcio `POST /api/v2/signingCert` API which
  returns a verifiable certificate signed by an ephemeral certificate authority.
* Mocked version of the Sigstore Rekor `POST /api/v1/log/entries` API which
  returns a log entry with a verifiable signed-entry timestamp (SET).

## To Do

* Mocked version of the Sigstore Timestmap Authority service.
* Mocked TUF repository which returns the key material necessary to
  verify artifacts returned from the other services.

## Prerequisites

- Node.js version >= 14.17.0

## Installation

```
npm install @sigstore/mock
```

## Usage

```javascript
const { mockFulcio, mockRekor } = require('@sigstore/mock')
```

```javascript
import { mockFulcio, mockRekor } from '@sigstore/mock'
```

### mockFulcio([options])
Sets-up a mock endpoint for the Fulcio `POST /api/v2/signingCert` API.

* `options` `<Object>`
  * `baseURL` `<string>`: Base URL for mocked Fulcio API server. Defaults to
    `'https://fulcio.sigstore.dev'`
  * `strict` `<boolean>`: Flag indicating whether or not the request payload
    will be parsed. When set to `true` the request must contain a well-formed
    OIDC token and a well-formed public key. The OIDC token does NOT need to be
    signed or contain a verifiable signature. The supplied public key will be
    part of the returned certificate. When set to `false` the request body will
    not be interpreted and a dummy OIDC token and key will be used to provision
    the certificate. Defaults to `true`.

### mockRekor([options])
Sets-up a mock endpoint for the Rekor `POST /api/v1/log/entries` API.

* `options` `<Object>`
  * `baseURL` `<string>`: Base URL for mocked Rekor API server. Defaults to
    `'https://rekor.sigstore.dev'`
  * `strict` `<boolean>`: Flag indicating whether or not the request payload
    will be parsed. When set to `true` the request must contain a well-formed
    JSON string. The supplied JSON object will be embedded in the returned
    log entry. When set to `false` the request body will not be interpreted
    and a dummy proposed entry  be used. Defaults to `true`.

