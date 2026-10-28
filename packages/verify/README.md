# @sigstore/verify &middot; [![npm version](https://img.shields.io/npm/v/@sigstore/verify.svg?style=flat)](https://www.npmjs.com/package/@sigstore/verify) [![CI Status](https://github.com/sigstore/sigstore-js/workflows/CI/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/ci.yml) [![Smoke Test Status](https://github.com/sigstore/sigstore-js/workflows/smoke-test/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/smoke-test.yml)

A library for verifying [Sigstore][1] signatures.

## Transparency log threshold

The `Verifier` option `tlogThreshold` sets the minimum number of transparency log entries required for verification (default: `1`). Entries are identified by their authenticated log ID and canonicalized body. Repeated bodies from the same log are rejected as duplicates, even if their log indices differ. The same body from different authenticated logs counts separately.

## Prerequisites

- Node.js version ^22.22.2 || ^24.15.0 || >=26.0.0

[1]: https://www.sigstore.dev
