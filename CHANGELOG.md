# sigstore

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
