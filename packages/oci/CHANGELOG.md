# @sigstore/oci

## 0.3.6

### Patch Changes

- 1c918fc: Remove extraneous field from referrers index

## 0.3.5

### Patch Changes

- 2f409eb: Fix bug when detecting support for the referrers API

## 0.3.4

### Patch Changes

- b0db256: Fix missing await in addArtifact

## 0.3.3

### Patch Changes

- fa50bae: Fix accept header when retrieving image manifest
- 70f4782: Support variants of the Docker Hub registry name

## 0.3.2

### Patch Changes

- 9605da8: Fix bug preventing failed API requests from being retried

## 0.3.1

### Patch Changes

- 9d300e8: Bump make-fetch-happen from 13.0.0 to 13.0.1

## 0.3.0

### Minor Changes

- b16d990: Removes AWS-specific logic for re-writing media type values

## 0.2.0

### Minor Changes

- ee3a521: Include `subject` and `artifactType` fields in artifact manifest for AWS ECR
- d1f0f5a: Remove Docker Hub from list of registries which are not compatible with OCI v1.1.0 image spec
- 61eeb07: Add new `getImageDigest` function

## 0.1.0

### Minor Changes

- 002a7a0: Initial release
