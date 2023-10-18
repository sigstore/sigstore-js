# @sigstore/mock

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
