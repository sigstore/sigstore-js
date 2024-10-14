# @sigstore/mock

## 0.8.0

### Minor Changes

- dfe67da: Drop support for node 16

### Patch Changes

- 271993f: Bump dependencies:

  - jose from 5.6.2 to 5.6.3
  - pkijs from 3.1.0 to 3.2.1

- fb80763: Bump dependencies:

  - jose from 5.6.3 to 5.7.0
  - nock from 13.5.4 to 13.5.5

- fcc52dc: Bump jose from 5.8.0 to 5.9.2
- 54674f3: Bump dependencies:

  - pkijs from 3.2.1 to 3.2.4
  - @peculiar/x509 from 1.11.0 to 1.12.1

- 5a2c116: Bump jose from 5.9.3 to 5.9.4
- 2b264a9: Bump @peculiar/x509 from 1.12.2 to 1.12.3
- ada9967: Bump jose from 5.7.0 to 5.8.0
- 5ff05d6: Bump dependencies:

  - @peculiar/x509 from 1.12.1 to 1.12.2
  - jose from 5.9.2 to 5.9.3

- 6f9376a: Bump jose from 5.4.0 to 5.6.2

## 0.7.5

### Patch Changes

- 7296bf4: Bump dependencies:

  - @peculiar/webcrypto from 1.4.6 to 1.5.0
  - @peculiar/x509 from 1.10.0 to 1.11.0
  - jose from 5.3.0 to 5.4.0
  - pkijs from 3.0.16 to 3.1.0

- 5eb4a07: Bump dependencies:

  - @peculiar/x509 from 1.9.7 to 1.10.0
  - jose from 5.2.4 to 5.3.0

## 0.7.4

### Patch Changes

- cf0c3ef: Bump @sigstore/protobuf-specs from 0.3.0 to 0.3.2

## 0.7.3

### Patch Changes

- 34e4efd: Bump jose from 5.2.3 to 5.2.4

## 0.7.2

### Patch Changes

- f5fcb16: Bump @peculiar/webcrypto from 1.4.5 to 1.4.6

## 0.7.1

### Patch Changes

- 4b19118: Bump pkijs from 3.0.15 to 3.0.16

## 0.7.0

### Minor Changes

- c1259bd: Support legacy-style certificate extensions in mock Fulcio service

### Patch Changes

- 385959b: Bump nock from 13.5.3 to 13.5.4
- 823341b: Bump jose from 5.2.2 to 5.2.3
- baa713a: Bump nock from 13.5.1 to 13.5.3

## 0.6.5

### Patch Changes

- 555dd8e: Bump @sigstore/protobuf-specs from 0.2.1 to 0.3.0
- 33647fd: Bump jose from 5.2.1 to 5.2.2

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
