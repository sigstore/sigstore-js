# @sigstore/verify

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
