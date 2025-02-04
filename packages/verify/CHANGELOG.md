# @sigstore/verify

## 2.1.0

### Minor Changes

- 74cc6c5: Bump @sigstore/protobuf-specs from 0.3.2 to 0.4.0

### Patch Changes

- Updated dependencies [74cc6c5]
  - @sigstore/bundle@3.1.0

## 2.0.0

### Major Changes

- f89faed: Drop support for node 16

### Patch Changes

- Updated dependencies [b869728]
- Updated dependencies [b78615b]
- Updated dependencies [9df66ee]
- Updated dependencies [2e58489]
  - @sigstore/bundle@3.0.0
  - @sigstore/core@2.0.0

## 1.2.1

### Patch Changes

- cf0c3ef: Bump @sigstore/protobuf-specs from 0.3.1 to 0.3.2
- Updated dependencies [cf0c3ef]
  - @sigstore/bundle@2.3.2

## 1.2.0

### Minor Changes

- c38961d: Support for verifying bundles with new v0.3 media type

### Patch Changes

- c38961d: Bump @sigstore/protobuf-specs from 0.3.0 to 0.3.1
- c38961d: Bump @sigstore/bundle from 2.2.0 to 2.3.1

## 1.1.1

### Patch Changes

- 46caed8: Fix bug related to loading RSA keys from the trusted key material
- Updated dependencies [46caed8]
  - @sigstore/core@1.1.0

## 1.1.0

### Minor Changes

- 555dd8e: Support for verifying v0.3 bundles

### Patch Changes

- 555dd8e: Bump @sigstore/protobuf-specs from 0.2.1 to 0.3.0
- Updated dependencies [555dd8e]
- Updated dependencies [555dd8e]
  - @sigstore/bundle@2.2.0

## 1.0.0

### Major Changes

- 7d90262: Promote to 1.0.0

### Patch Changes

- f05be96: Update Rekor verification to handle checkpoint values which do no include timestamps (https://github.com/sigstore/rekor/pull/1888)
- Updated dependencies [7d90262]
  - @sigstore/core@1.0.0

## 0.1.0

### Minor Changes

- bf1d432: Export `VerificationPolicy` type
- 08b7957: Enable verification of RFC3161 timestamps
- afb08f6: Add support for verifying identity of certificate issuer
- 6f9c662: Extract verification code into dedicated package

### Patch Changes

- 29a25e5: Read RFC3161 timestamps during verification
- 45903bc: Expose public `signature` property on `SignatureContent` interface
- e5f1875: Fix logic to extract issuer from Fulcio certificate
- Updated dependencies [6cdf7ef]
- Updated dependencies [6869511]
- Updated dependencies [6a6bfbc]
- Updated dependencies [57bec90]
- Updated dependencies [34c3856]
- Updated dependencies [922a1be]
  - @sigstore/core@0.2.0
  - @sigstore/bundle@2.1.1
