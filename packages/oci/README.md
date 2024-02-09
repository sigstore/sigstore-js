# @sigstore/oci &middot; [![npm version](https://img.shields.io/npm/v/@sigstore/oci.svg?style=flat)](https://www.npmjs.com/package/@sigstore/oci) [![CI Status](https://github.com/sigstore/sigstore-js/workflows/CI/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/ci.yml) [![Smoke Test Status](https://github.com/sigstore/sigstore-js/workflows/smoke-test/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/smoke-test.yml)

Attach artifacts to images in OCI registries.

## Prerequisites

- Node.js version >= 16.14.0

## Installation

```
npm install @sigstore/oci
```

## Usage

```javascript
const { attachArtifactToImage } = require('@sigstore/oci');
```

```javascript
import { attachArtifactToImage } from '@sigstore/oci';
```

### attachArtifactToImage(options)

Uploads the provided artifact to the registry and associates it with an OCI image.

- `options` `Object`

  - `artifact` `Buffer`: Bytes of the artifact to upload.
  - `mediaType` `string`: Content type to assign to the artifact.
  - `imageName` `string`: Fully-qualified name of the image to which the artifact should be associated.
  - `imageDigest` `string`: Digest of the image to which the artifact should be associated. Should be of the form `<alg>:<digest>`.
  - `credentials` `Object`
    - `username` `string`: Username to use when authenticating with the registry.
    - `password` `string`: Password to use when authenticating with the registry.
  - `annotations` `Record<string, string>`: Arbitrary name/value pairs to be associated with artifact.

### getRegistryCredentials(imageName)

Reads the local `$HOME/.docker/config.json` file and returns the credentials associated with the image's registry.

- `imageName` `string`: Fully-qualified name of the image from which to extract the registry hostname.

Returns a `Credentials` object with the following keys:

- `username` `string`
- `password` `string`

Throws if the Docker config cannot be located or if there are no credentials for the specified registry.
