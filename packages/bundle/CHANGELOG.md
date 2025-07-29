# @sigstore/bundle

## 4.0.0

### Major Changes

- 383e200: Drop support for node 18

## 3.1.0

### Minor Changes

- 74cc6c5: Bump @sigstore/protobuf-specs from 0.3.2 to 0.4.0

## 3.0.0

### Major Changes

- b869728: `toDSSEBundle` and `toMessageSignatureBundle` generate v0.3 bundles by default
- 9df66ee: Drop support for node 16

## 2.3.2

### Patch Changes

- cf0c3ef: Bump @sigstore/protobuf-specs from 0.3.1 to 0.3.2

## 2.3.1

### Patch Changes

- c5f0f79: Fix bug in regex for matching media types

## 2.3.0

### Minor Changes

- 4c48c22: Add support for building v0.3 bundles

## 2.2.0

### Minor Changes

- 555dd8e: Support for validating v0.3 bundles

### Patch Changes

- 555dd8e: Bump @sigstore/protobuf-specs from 0.2.1 to 0.3.0

## 2.1.1

### Patch Changes

- 57bec90: Update `bundleFromJSON` to perform full bundle validation

## 2.1.0

### Minor Changes

- 70cb986: Generate v0.2 Sigstore bundles

## 2.0.0

### Major Changes

- d0053a3: Drop node 14 support

### Patch Changes

- 06ea684: Bump @sigstore/protobuf-specs from 0.2.0 to 0.2.1

## 1.1.0

### Minor Changes

- 84eee0b: Move bundle construction helpers to the `@sigstore/bundle` package.

## 1.0.0

### Major Changes

- a388e25: Promoting to 1.0.0

### Minor Changes

- f1b8bad: Export bundle media type constants, refine `SerializedTLogEntry` type
- 2a5f500: Initial release
- 2a869ba: export `envelopeToJSON`/`envelopeFromJSON` functions for serialization/deserialization of DSSE envelopes

### Patch Changes

- e0c16ec: Bump @sigstore/protobuf-specs from 0.1.0 to 0.2.0
