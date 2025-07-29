# @sigstore/sign

## 4.0.0

### Major Changes

- 383e200: Bump make-fetch-happen from 14.x to 15.x
- 383e200: Drop support for node 18

### Patch Changes

- Updated dependencies [383e200]
  - @sigstore/bundle@4.0.0
  - @sigstore/core@3.0.0

## 3.1.0

### Minor Changes

- 74cc6c5: Bump @sigstore/protobuf-specs from 0.3.2 to 0.4.0

### Patch Changes

- Updated dependencies [74cc6c5]
  - @sigstore/bundle@3.1.0

## 3.0.0

### Major Changes

- f84ca10: Drop support for node 16
- f84ca10: Bump proc-log from 4.2.0 to 5.0.0
- 54c1b04: Default `DSSEBundleBuilder` to generating v0.3 bundles
- f84ca10: Bump make-fetch-happen from 13.0.1 to 14.0.1
- 64cae89: Default `RekorWitness` to generating "dsse" entries instead of "intoto"

### Patch Changes

- Updated dependencies [b869728]
- Updated dependencies [b78615b]
- Updated dependencies [9df66ee]
- Updated dependencies [2e58489]
  - @sigstore/bundle@3.0.0
  - @sigstore/core@2.0.0

## 2.3.2

### Patch Changes

- cf0c3ef: Bump @sigstore/protobuf-specs from 0.3.1 to 0.3.2
- Updated dependencies [cf0c3ef]
  - @sigstore/bundle@2.3.2

## 2.3.1

### Patch Changes

- 9d300e8: Bump make-fetch-happen from 13.0.0 to 13.0.1
- 88e91c7: Fix bug preventing failed API requests from being retried

## 2.3.0

### Minor Changes

- 77e9e17: Updates the `DSSEBundleBuilder` with a new `singleCertificate` option which will trigger the creation of v0.3 Sigstore bundles

### Patch Changes

- c32327a: Bump @sigstore/protobuf-specs from 0.3.0 to 0.3.1

## 2.2.3

### Patch Changes

- 555dd8e: Bump @sigstore/protobuf-specs from 0.2.1 to 0.3.0
- Updated dependencies [555dd8e]
- Updated dependencies [555dd8e]
  - @sigstore/bundle@2.2.0

## 2.2.2

### Patch Changes

- Updated dependencies [7d90262]
  - @sigstore/core@1.0.0

## 2.2.1

### Patch Changes

- 34c3856: Integrate `@sigstore/core` package
- Updated dependencies [6cdf7ef]
- Updated dependencies [6869511]
- Updated dependencies [6a6bfbc]
- Updated dependencies [57bec90]
- Updated dependencies [34c3856]
- Updated dependencies [922a1be]
  - @sigstore/core@0.2.0
  - @sigstore/bundle@2.1.1

## 2.2.0

### Minor Changes

- c0a43d5: Expose `entryType` option on `RekorWitness` constructor

## 2.1.0

### Minor Changes

- 9256f86: Export default Fulcio and Rekor URLs
- 70cb986: Generate v0.2 Sigstore bundles
- fca33dc: Surface error messages returned from Sigstore services in thrown errors

### Patch Changes

- 4a386dc: Better error handling when an invalid OIDC token is encountered
- Updated dependencies [70cb986]
  - @sigstore/bundle@2.1.0

## 2.0.0

### Major Changes

- d0053a3: Drop node 14 support
- d0053a3: Bump `make-fetch-happen` from 11.0.0 to 13.0.0

### Patch Changes

- 06ea684: Bump @sigstore/protobuf-specs from 0.2.0 to 0.2.1
- Updated dependencies [06ea684]
- Updated dependencies [d0053a3]
  - @sigstore/bundle@2.0.0

## 1.0.0

### Major Changes

- abcebbf: Promote to 1.0 release

### Minor Changes

- fe31654: Rename `MessageBundleBuilder` class to `MessageSignatureBundleBuilder`
- 5de42a0: Initial release
- 84eee0b: Move bundle construction helpers to the `@sigstore/bundle` package.

### Patch Changes

- Updated dependencies [84eee0b]
  - @sigstore/bundle@1.1.0
