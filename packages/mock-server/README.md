# @sigstore/mock-server

HTTP server which provides mocked versions of the core Sigstore services:
Fulcio, Rekor, and Timestamp Authority. This is for testing purposes only and
SHOULD NOT be used in production scenarios.

The server runs all of the all of the endpoints on a single port and provides
everything you need to exercise basic signing and verification workflows (online
transparencly log verification is not yet supported). The key material for all
of the mocked services is collected into a ["trusted_root.json"][1] and served
from a mocked TUF repository.

This is a private package and not published to the registry.

## Usage

To start the server run the following command:

```
npm run start
```

## Endpoints

The server supports the following endpoints

### `POST /api/v2/signingCertificate`

Simulates the Fulcio endpoint for requesting a signing certificate.

### `POST /api/v1/logEntries`

Simulates the Rekor endpoint for adding an entry to the transparency log.

### `POST /api/v1/timestamp`

Simulates the Timestamp Authority endpoint for requesting a signed timestamp.

### `GET /targets/trusted_root.json`

TUF Target containing the key material for the mocked services.

### `GET /targets.json`

TUF metadata for the "trusted_root.json" target.

### `GET /snapshot.json`

TUF metadata for the snapshot role.

### `GET /timestamp.json`

TUF metadata for the timestamp role.

### `GET /1.root.json`

Root TUF metadata file containing keys/signatures for all of the TUF roles.

[1]: https://github.com/sigstore/protobuf-specs/blob/629b7aa96a81a3c5883d064ecb207a1b60cc0724/protos/sigstore_trustroot.proto#L83-L101
