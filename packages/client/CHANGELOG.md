# sigstore

## 1.5.2

### Patch Changes

- 2f89e43: Update Fulcio client to handle responses with detached SCTs

## 1.5.1

### Patch Changes

- cab068e: Propagate `retry`/`timeout` options to the Timestamp Authority client

## 1.5.0

### Minor Changes

- f4c677e: Generated bundle excludes Fulcio root and intermediate certificates
- 5ca42a0: New `tsaServerURL` option for requesting a timestamp from a Timestamp Authority API
- 4e715c9: Exposes a new `tuf.client` function which returns a client for retrieving targets from the Sigstore TUF repository.
- 4b97516: New `tlogUpload` option for `sign` and `attest` to control signature uploads to the transparency log
- f927296: New `retry` and `timeout` options to control fetch behavior when errors occur

### Patch Changes

- 2e5e733: Certificate chain verification enforces pathlen constraint for CA certs
- 3205ce9: Updates certificate verification to ignore all but the first certificate present in the bundle
- bb2006b: Updating embedded Sigstore TUF root to v7

## 1.4.0

### Minor Changes

- 99093bb: add specific errors codes for `InternalError`s
- 99093bb: export error classes

## 1.3.2

### Patch Changes

- 6ba4fd1: Print the rekor search entry when running the `sigstore attest` command

## 1.3.1

### Patch Changes

- d2d0702: Update CLI sign cmd to output a link to search.sigstore.dev

## 1.3.0

### Minor Changes

- c2e3dd5: Add support for verification of certificate extension values encoded as UTF8String
- 6fd6e22: Exposes a new `tuf.getTarget` function to retrieve targets from the Sigstore TUF repository
- da0bfd7: Added new token provider for looking up OIDC tokens in the SIGSTORE_ID_TOKEN environment variable.

### Patch Changes

- 9dbb26d: Use CDN-backend endpoint to fetch TUF root material
- 341b7bd: Update dependency - tuf-js@1.1.3

## 1.2.0

### Minor Changes

- 54d6de4: Adds new `redirectURL` config option when signing with an OAuth identity provider

### Patch Changes

- 8b9375f: Update to tuf-js@1.1.2
- 8f9f994: Use the Fulcio v2 API for requesting signing certificates

## 1.1.1

### Patch Changes

- 62de8cd: Unbundles the @sigstore/protobuf-specs dependency

## 1.1.0

### Minor Changes

- 49709fc: Exposes new `tufMirrorURL` and `tufRootPath` options to the `verify` function
- 49709fc: Relocates the TUF cache to a platform-specific app data directory

### Patch Changes

- 6b75981: Consume the trusted_root.json target from the Sigstore TUF repository
