# @sigstore/core

## 3.1.0

### Minor Changes

- 5ffadc0: Add support for parsing RSA-signed certificates

## 3.0.0

### Major Changes

- 383e200: Drop support for node 18

## 2.0.0

### Major Changes

- b78615b: Remove `hash` function in core package
- 2e58489: Drop support for node 16

## 1.1.0

### Minor Changes

- 46caed8: Update `createPublicKey` to support both "spki" and "pkcs1" key types

## 1.0.0

### Major Changes

- 7d90262: Promote to 1.0.0

## 0.2.0

### Minor Changes

- 6869511: Add support for parsing RFC3161 signed timestamps
- 34c3856: add `encoding` and `dsse` utility modules

### Patch Changes

- 6cdf7ef: Bug fix for parsing ASN.1 date/time values which include milliseconds
- 6a6bfbc: Add more checks to the `RFC3161Timestamp.verify` method
- 922a1be: Ensure the `isCA` value for the `X509BasicConstraintsExtension` defaults to `false` if no other value is present

## 0.1.0

### Minor Changes

- 5fbbe86: Extract common code into core package
