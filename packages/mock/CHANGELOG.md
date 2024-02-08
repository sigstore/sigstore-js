# @sigstore/mock

## 0.6.4

### Patch Changes

- 43cf328: Bump dependencies:

  - @peculiar/x509 from 1.9.6 to 1.9.7
  - jose from 5.2.0 to 5.2.1

- 8237a21: Bump dependencies:

  - nock from 13.5.0 to 13.5.1
  - @peculiar/webcrypto from 1.4.3 to 1.4.5

- b2e6bed: Bump nock from 13.4.0 to 13.5.0

## 0.6.3

### Patch Changes

- 123389f: Introduce intermediate certificate for issuing RFC3161 timestamps
- 8cbcd04: Bump @peculiar/x509 from 1.9.5 to 1.9.6
- 2dd55a0: Remove extra level of OCTET STRING nesting in mocked RFC3161 timestamp response
- 9318c9c: Bump jose from 5.1.3 to 5.2.0
- 123389f: Fix encoding for TSA-issued timestamps

## 0.6.2

### Patch Changes

- 84bc758: Bump jose from 5.1.0 to 5.1.1
- 5957b94: Bump jose from 5.0.1 to 5.0.2
- 532612c: Bump jose from 5.0.2 to 5.1.0
- b7c386e: Bump dependencies:

  - nock from 13.3.4 to 13.3.6

- fe1530d: Bump dependencies:

  - jose from 5.1.1 to 5.1.2
  - nock from 13.3.8 to 13.4.0

- 82d3150: Bump jose from 4.15.4 to 5.0.1
- b1c3f06: Bump nock from 13.3.6 to 13.3.8
- f68e429: Bump jose from 5.1.2 to 5.1.3

## 0.6.1

### Patch Changes

- 69fdfdd: Bump dependencies:

  - nock from 13.3.3 to 13.3.4
  - jose from 4.15.2 to 4.15.4

## 0.6.0

### Minor Changes

- b344a14: Allow explicit clock control for mocked services
- 76384c1: Add "issuer" extension to certificates issued by mock Fulcio

### Patch Changes

- 9d3ccd6: Rekor mock running in non-strict mode creates a valid entry
- aa459dd: Bump jose from 4.15.1 to 4.15.2
- e26aa53: Bump jose from 4.14.6 to 4.15.1

## 0.5.0

### Minor Changes

- 7a4efe0: Configurable keys for mock services

### Patch Changes

- 442c57f: Bump dependencies:

  - jose from 4.14.4 to 4.14.6

- 13e78ac: Fix bug in mocked inclusion proof calculation

## 0.4.0

### Minor Changes

- ef1a163: Remove extraneous `@tufjs/repo-mock` dependency

### Patch Changes

- 5e5bd85: Bump @peculiar/x509 from 1.9.3 to 1.9.5

## 0.3.0

### Minor Changes

- d0053a3: Drop node 14 support

### Patch Changes

- 4e49006: Bump @tufjs/repo-mock from 1.4.0 to 2.0.0
- 1e0fb61: Bump nock from 13.3.2 to 13.3.3
- 06ea684: Bump @sigstore/protobuf-specs from 0.2.0 to 0.2.1
- c8de4e9: Fix incorrect dependency reference in `package.json`

## 0.2.0

### Minor Changes

- e8f258d: Add verifiable inclusion proof to mock tlog response

### Patch Changes

- 917f48c: Fix bug in inclusion proof returned with mocked transaction log enries

## 0.1.1

### Patch Changes

- e0c16ec: Bump @sigstore/protobuf-specs from 0.1.0 to 0.2.0
- 7b5af13: Bump nock from 13.3.1 to 13.3.2

## 0.1.0

### Minor Changes

- 3681515: Initial release

### Patch Changes

- 470e1da: Bump pkijs from 3.0.14 to 3.0.15
