# @sigstore/cli

## 0.8.1

### Patch Changes

- f277121: Bump `@oclif/core` from 3.26.6 to 4.0.6

## 0.8.0

### Minor Changes

- 66d28b0: Update `verify` command to verify v0.3 Sigstore bundles
- 66d28b0: Update `attest` command to generate v0.3 Sigstore bundles

## 0.7.1

### Patch Changes

- Updated dependencies [b16d990]
  - @sigstore/oci@0.3.0

## 0.7.0

### Minor Changes

- e4a79f6: Add new `attach` command for pushing attestations to an OCI registry

### Patch Changes

- 823341b: Bump openid-client from 5.6.4 to 5.6.5
- Updated dependencies [ee3a521]
- Updated dependencies [d1f0f5a]
- Updated dependencies [61eeb07]
  - @sigstore/oci@0.2.0

## 0.6.0

### Minor Changes

- c949aa7: Add most verify options to `sigstore verify` subcommand
- 4089730: Add `tuf-force-cache` flag to `verify` command
- 4089730: Add `cache-path` flag to `initialize` command

### Patch Changes

- bfa5eeb: Bump openid-client from 5.6.2 to 5.6.4
- 9318c9c: Bump openid-client from 5.6.1 to 5.6.2
- Updated dependencies [4089730]
- Updated dependencies [af76b1d]
- Updated dependencies [34c3856]
  - sigstore@2.2.0

## 0.5.0

### Minor Changes

- 4cd344d: Drop support for node 16

### Patch Changes

- 69fdfdd: Bump dependencies:

  - openid-client from 5.6.0 to 5.6.1

- 97516ef: Bump @oclif/plugin-help from 5.2.20 to 6.0.3
- cb81e53: Bump dependencies:

  - @oclif/color from 1.0.12 to 1.0.13

## 0.4.0

### Minor Changes

- cc42dae: Add timeout flag to attest command

### Patch Changes

- 9173d9c: Bump dependencies:

  - @oclif/color from 1.0.11 to 1.0.12
  - @oclif/plugin-help from 5.2.19 to 5.2.20

- c6d6498: Bump @oclif/core from 2.15.0 to 3.0.1
- f52ee51: Bump openid-client from 5.5.0 to 5.6.0

## 0.3.0

### Minor Changes

- e3e725c: Add `initialize` command to bootstrap local TUF cache

### Patch Changes

- c4489fc: Bump openid-client from 5.4.3 to 5.5.0

## 0.2.1

### Patch Changes

- 7f8d194: Bump @oclif/color from 1.0.10 to 1.0.11
- Updated dependencies [70cb986]
  - sigstore@2.1.0

## 0.2.0

### Minor Changes

- d0053a3: Drop node 14 support

### Patch Changes

- Updated dependencies [829e123]
- Updated dependencies [4e49006]
- Updated dependencies [4455f7f]
- Updated dependencies [d5060c0]
- Updated dependencies [d0053a3]
- Updated dependencies [3bd0fbb]
- Updated dependencies [e36bbfa]
- Updated dependencies [06ea684]
- Updated dependencies [3bd0fbb]
  - sigstore@2.0.0

## 0.1.2

### Patch Changes

- a322817: Bump @oclif/color from 1.0.9 to 1.0.10
- Updated dependencies [75ba6cd]
- Updated dependencies [e44f05c]
- Updated dependencies [9b8c140]
  - sigstore@1.9.0

## 0.1.1

### Patch Changes

- c0a4baa: Bump @oclif/color from 1.0.6 to 1.0.7
- 8b7d0cf: Bump @oclif/color from 1.0.8 to 1.0.9
- 580469a: Bump @oclif/color from 1.0.7 to 1.0.8
- b7ea8c8: Bump openid-client from 5.4.2 to 5.4.3
- Updated dependencies [e0c16ec]
- Updated dependencies [6abe9ec]
- Updated dependencies [f1b8bad]
- Updated dependencies [d9b1540]
  - sigstore@1.8.0

## 0.1.0

### Minor Changes

- 439343b: Use new OAuth identity provider for retrieving OIDC tokens in non-CI environments

### Patch Changes

- 0d9acd4: adds OAuth identity provider in support of interactive authentication flows for the `attest` command
- a923d32: Bump @oclif/color from 1.0.5 to 1.0.6
- 2bd39a2: Bump @oclif/color from 1.0.4 to 1.0.5
- Updated dependencies [4fdf826]
- Updated dependencies [f72e2b2]
- Updated dependencies [5ea8b63]
- Updated dependencies [84fd931]
  - sigstore@1.6.0

## 0.0.5

### Patch Changes

- 45980a3: Fix support for `--tlog-upload`/`--no-tlog-upload` flag

## 0.0.4

### Patch Changes

- 929d5d2: Fix to allow `--tlog-upload` flag to be negated with `--no-tlog-upload`
- Updated dependencies [2f89e43]
  - sigstore@1.5.2

## 0.0.3

### Patch Changes

- e8d440e: Add missing `@oclif/color` dependency

## 0.0.2

### Patch Changes

- 630f2fa: Initial release
- Updated dependencies [cab068e]
  - sigstore@1.5.1
