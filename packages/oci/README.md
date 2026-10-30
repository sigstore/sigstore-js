# @sigstore/oci &middot; [![npm version](https://img.shields.io/npm/v/@sigstore/oci.svg?style=flat)](https://www.npmjs.com/package/@sigstore/oci) [![CI Status](https://github.com/sigstore/sigstore-js/workflows/CI/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/ci.yml) [![Smoke Test Status](https://github.com/sigstore/sigstore-js/workflows/smoke-test/badge.svg)](https://github.com/sigstore/sigstore-js/actions/workflows/smoke-test.yml)

Attach artifacts to images in OCI registries.

## Prerequisites

- Node.js version ^22.22.2 || ^24.15.0 || >=26.0.0

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
  - `fetchOpts` `RegistryFetchOptions`: Network options described in [Network policy](#network-policy).

### getImageDigest(options)

Returns the digest of an image tag.

- `imageName` `string`: Fully-qualified image name, without a tag or digest.
- `imageTag` `string`: Tag to resolve.
- `credentials` `Credentials`: Registry username and password.
- `fetchOpts` `RegistryFetchOptions`: Optional network options.

### Network policy

By default, requests require HTTPS and public network destinations. This applies
to the registry, token services, every redirect, and blob upload locations.
Loopback, private, link-local, metadata, multicast, reserved, and documentation
addresses are blocked, including IPv4-mapped IPv6 addresses. IPv6 destinations
must be in `2000::/3`, excluding special-purpose, documentation, and transition
ranges.

Public cross-origin token services, including Docker Hub's token service, work
without an origin allowlist. Registry credentials and Docker custom headers do
not accompany cross-origin blob uploads. Credential headers stay stripped after
a redirect leaves their origin, even if a later hop returns. OAuth credential
bodies can follow same-origin 307/308 redirects, but cross-origin redirects that
retain those bodies fail. HTTPS-to-HTTP transitions always fail.

A registry can select any public HTTPS token service. Supply only credentials
intended for that registry; address validation does not establish that the token
service is trustworthy.

For intentional private or local deployments, set
`fetchOpts.allowedPrivateOrigins` in either public API. Each entry must be an
exact origin (`scheme://hostname:port`), without userinfo, a path, query, or
fragment. The exception permits non-public addresses and HTTP only at that
origin. It does not authorize another hostname, scheme, or port. List a private
token service or upload destination separately if your registry uses one.

```javascript
import { getImageDigest, attachArtifactToImage } from '@sigstore/oci';

const credentials = {
  username: 'user',
  password: process.env.REGISTRY_PASSWORD,
};
const fetchOpts = {
  allowedPrivateOrigins: [
    'http://localhost:5000',
    'https://auth.internal:8443',
  ],
};
const imageName = 'localhost:5000/example/image';
const imageDigest = await getImageDigest({
  imageName,
  imageTag: 'latest',
  credentials,
  fetchOpts,
});
await attachArtifactToImage({
  imageName,
  imageDigest,
  credentials,
  fetchOpts,
  artifact: Buffer.from('example'),
  mediaType: 'text/plain',
});
```

Only configure exceptions for services you trust. An exception authorizes every
address that its hostname resolves to. HTTP sends credentials without transport
encryption. A caller-selected private registry is not exempt unless you list its
origin explicitly. HTTP registry selection requires an explicit HTTP exception;
registries otherwise use HTTPS.

Address checks run in the socket's DNS lookup and validate every returned
address before the transport connects. Retries repeat this check. The transport
does not reuse sockets across requests, so a connection created under one
origin exception cannot be reused under another policy. TLS still verifies the
requested hostname.

This is an IP-address policy, not an egress firewall. It cannot detect public IP
addresses that your network routes to private infrastructure. The address ranges
also need maintenance as address allocations change.

Proxies configured with `fetchOpts.proxy` or environment variables (names are
case-insensitive) are honored. HTTPS requests use `HTTPS_PROXY`; HTTP requests to
an allowed origin use `HTTPS_PROXY`, `HTTP_PROXY`, or `PROXY`, in that order.
`ALL_PROXY` is not used. Hosts matched by `fetchOpts.noProxy` or `NO_PROXY`
(domain-suffix match, case-insensitive) connect directly with the DNS address
check. Scheme, literal-address, `localhost`, redirect, and credential rules still
apply to proxied requests. However, the proxy resolves the destination hostname
itself, so the DNS address check described above applies only to direct
connections. Through a proxy, a hostname that resolves to a private address is
reachable if the proxy permits it. Rely on the proxy's egress policy to block
internal destinations. Other fetch options are `retry` and `timeout`.

Network-policy failures are not retried and do not trigger OAuth-to-distribution
authentication fallback. Public API failures retain an `OCIError` with the
underlying policy error in `cause`.

The CLI accepts the same exceptions as repeatable `sigstore attach` flags:

```shell
sigstore attach --attestation bundle.json \
  --allow-private-origin http://localhost:5000 \
  --allow-private-origin https://auth.internal:8443 \
  localhost:5000/example/image:latest
```

The flags apply to both digest lookup and artifact upload.

### getRegistryCredentials(imageName)

Reads the local Docker config file and returns the credentials associated with the image's registry. Uses `$DOCKER_CONFIG/config.json` when `DOCKER_CONFIG` is set; otherwise `$HOME/.docker/config.json`.

- `imageName` `string`: Fully-qualified name of the image from which to extract the registry hostname.

Returns a `Credentials` object with the following keys:

- `username` `string`
- `password` `string`

Throws if the Docker config cannot be located or if there are no credentials for the specified registry.
