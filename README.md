# sigstore-js

⚠️ This project is not ready for general-purpose use! ⚠️

A tool for signing and verifying signatures using JavaScript.
One of the intended uses is to sign and verify npm packages
but it can be used to sign and verify any file.

## Features

* Support for signing npm packages using an OpenID Connect identity
* Support for publishing signatures to a [Rekor][1] instance
* Support for verifying signatures on npm packages

## TODO

* Verify audience of received identity token
* Verify signing certificate
  * Verify against Fulcio certificate chain
  * Verify the [Signed Certificate Timestamp]([url](https://datatracker.ietf.org/doc/html/rfc6962)) (SCT) against the transparency log's public key
* Verification of Rekor response
  * Verify the record's inclusion proof
  * Verify signed entry timestamp
* Support offline and online signature verification
* Retrieve root cert and public keys via TUF client

## Prerequisites

- Node.js version 16+ (LTS)

### Updating protobufs

[Docker](https://docs.docker.com/engine/install/) is required to generate protobufs for the `.sigstore` bundle format.

Install Docker on MacOS using [Homebrew](https://brew.sh/):

```
brew install --cask docker && open -a Docker
```

View [Docker install instructions](https://docs.docker.com/engine/install/) for other platforms.

## Updating .sigstore bundle protobufs

Update the Git `REF` in `hack/generate-bundle-types` from the [sigstore/cosign](https://github.com/sigstore/cosign) repository.

Generate TypeScript protobufs (should update files in scr/types/bundle/\_\_generated\_\_):

```
npm run codegen:bundle
```

## Updating Rekor Types

Update the git `REF` in `hack/generate-rekor-types` from the [sigstore/rekor](https://github.com/sigstore/rekor) repository.

Generate TypeScript types (should update files in scr/types/rekor/\_\_generated\_\_):

```
npm run codegen:rekor
```

## Demo

### Set-up

Start by cloning this repo then, from the root of the repo, execute the
following to install the dependencies and transpile the TypeScript source:

```
$ npm install && npm run build
```

### Signing

First generate the artifact to be signed:

```
$  npm pack

npm notice
npm notice 📦  sigstore@0.0.0
npm notice === Tarball Contents ===
npm notice 354B  README.md
npm notice 58B   bin/sigstore.js
npm notice 2.3kB dist/cli/index.js
npm notice 1.3kB dist/crypto.js
npm notice 345B  dist/dsse.js
npm notice 516B  dist/error.js
npm notice 1.5kB dist/fulcio.js
npm notice 1.9kB dist/identity/ci.js
npm notice 1.3kB dist/identity/gha.js
npm notice 1.0kB dist/identity/index.js
npm notice 1.3kB dist/identity/issuer.js
npm notice 6.4kB dist/identity/oauth.js
npm notice 77B   dist/identity/provider.js
npm notice 260B  dist/index.js
npm notice 3.4kB dist/rekor.js
npm notice 2.9kB dist/sign.js
npm notice 2.9kB dist/sigstore.js
npm notice 1.5kB dist/util.js
npm notice 1.7kB dist/verify.js
npm notice 1.3kB package.json
npm notice === Tarball Details ===
npm notice name:          sigstore
npm notice version:       0.0.0
npm notice filename:      sigstore-0.0.0.tgz
npm notice package size:  8.6 kB
npm notice unpacked size: 32.4 kB
npm notice shasum:        44373924818c21f235f7e5aac514b172f1966243
npm notice integrity:     sha512-E+IgEuBoN6SQP[...]gKx2Bnuuj9Xcg==
npm notice total files:   20
npm notice
sigstore-0.0.0.tgz
```

Generate a signature for the package with the following:

```
$ ./bin/sigstore.js sign ./sigstore-0.0.0.tgz > bundle.sigstore

Created entry at index 4524464, available at
https://rekor.sigstore.dev/api/v1/log/entries?logIndex=4524464
```

You should see that a browser window is opened to the Sigstore OAuth page.
After authenticating with one of the available idenity providers, a signature
bundle will be generated and written to the file named "signature".

```
$ cat bundle.sigstore | jq

{
  "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
  "timestampVerificationData": {
    "tlogEntries": [
      {
        "logIndex": "4524464",
        "logId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=",
        "kindVersion": {
          "kind": "hashedrekord",
          "version": "0.0.1"
        },
        "integratedTime": "1665008899",
        "inclusionPromise": "MEQCIEI1EN2M0ShxStSBfoaS+mmDnk0Yhl68pjyMZ77WJrdNAiB7MDvTJ6+YbznLR1BhwKANUH1PtoorXnsjBnSDvs943Q=="
      }
    ],
    "rfc3161Timestamps": []
  },
  "verificationMaterial": {
    "x509CertificateChain": {
      "certificates": [
        "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"
      ]
    }
  },
  "messageSignature": {
    "messageDigest": {
      "algorithm": "SHA2_256",
      "digest": "FArN5VHf77/gtqmyQJ3vaL8t7LskOE8ThkOZlGJHaTw="
    },
    "signature": "MEUCID/iVOISFCfZXEFW3IrcWXQgLDfPHRxPZBWlgDOGmXmlAiEAgi02Imw+bFQlIKeyKKpk0i60KRw7djRkA/NY6LKhI5A="
  }
}
```

You'll see that the signature bundle contains the SHA256 digest of the
artifact, the signature, the signing certificate and metadata about the
entry which was made in Rekor.

You can extract and view the signing certificate with the following:
```
$ cat bundle.sigstore | jq --raw-output '.verificationMaterial.x509CertificateChain.certificates[0]' | base64 -d | openssl x509 -inform der -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            46:4d:7a:bf:65:b1:59:7f:97:c2:d9:9d:91:48:7e:1b:e5:08:b4:fa
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: O = sigstore.dev, CN = sigstore-intermediate
        Validity
            Not Before: Oct  5 22:28:19 2022 GMT
            Not After : Oct  5 22:38:19 2022 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:8d:f5:3a:26:c9:e2:7d:24:cc:99:1d:d1:52:81:
                    67:c9:51:09:d9:05:1a:a7:5b:66:a3:27:84:0b:4d:
                    9e:fc:dc:03:f4:9f:c1:d7:88:e7:d5:08:a8:a5:0a:
                    47:fd:f9:9b:d8:ef:ce:7c:d0:5c:2d:56:30:f7:fc:
                    01:13:04:76:fc
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                Code Signing
            X509v3 Subject Key Identifier: 
                AE:CD:A1:C5:18:1C:64:25:74:6C:B9:8D:F6:AD:E0:25:1B:27:2B:71
            X509v3 Authority Key Identifier: 
                DF:D3:E9:CF:56:24:11:96:F9:A8:D8:E9:28:55:A2:C6:2E:18:64:3F
            X509v3 Subject Alternative Name: critical
                email:brian@dehamer.com
            1.3.6.1.4.1.57264.1.1: 
                https://github.com/login/oauth
            CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 08:60:92:F0:28:52:FF:68:45:D1:D1:6B:27:84:9C:45:
                                67:18:AC:16:3D:C3:38:D2:6D:E6:BC:22:06:36:6F:72
                    Timestamp : Oct  5 22:28:19.234 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:46:02:21:00:83:8B:17:2E:4A:D6:E3:D6:D4:90:25:
                                19:52:74:8E:81:72:4F:8F:A6:0D:4E:27:DE:58:65:63:
                                0D:0D:92:EC:75:02:21:00:8A:83:15:8B:0D:86:D6:87:
                                9C:99:A9:8E:44:43:E3:93:3F:23:55:BC:73:4B:45:FA:
                                CF:76:07:65:15:15:C3:B8
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:66:02:31:00:c1:da:2a:2a:2a:4e:8a:3e:20:f6:37:87:99:
        fb:8e:5a:9e:40:d2:d4:84:04:de:5f:1e:58:da:c4:68:2c:0a:
        ac:cc:68:f1:67:e5:31:e3:11:5c:85:a1:5e:42:44:ff:3a:02:
        31:00:be:eb:da:c9:39:58:a3:5b:c0:84:4a:8a:c3:a1:b6:a4:
        34:2e:e1:1a:f7:4c:03:40:bc:11:90:7f:ff:93:e1:be:72:af:
        39:bc:60:00:6a:6c:56:98:a3:1f:4e:b9:12:77
-----BEGIN CERTIFICATE-----
MIICojCCAiegAwIBAgIURk16v2WxWX+XwtmdkUh+G+UItPowCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjIxMDA1MjIyODE5WhcNMjIxMDA1MjIzODE5WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEjfU6JsnifSTMmR3RUoFnyVEJ2QUap1tmoyeE
C02e/NwD9J/B14jn1QiopQpH/fmb2O/OfNBcLVYw9/wBEwR2/KOCAUYwggFCMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUrs2h
xRgcZCV0bLmN9q3gJRsnK3EwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzAB
AQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGLBgorBgEEAdZ5AgQC
BH0EewB5AHcACGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3IAAAGDqkOU
ogAABAMASDBGAiEAg4sXLkrW49bUkCUZUnSOgXJPj6YNTifeWGVjDQ2S7HUCIQCK
gxWLDYbWh5yZqY5EQ+OTPyNVvHNLRfrPdgdlFRXDuDAKBggqhkjOPQQDAwNpADBm
AjEAwdoqKipOij4g9jeHmfuOWp5A0tSEBN5fHljaxGgsCqzMaPFn5THjEVyFoV5C
RP86AjEAvuvayTlYo1vAhEqKw6G2pDQu4Rr3TANAvBGQf/+T4b5yrzm8YABqbFaY
ox9OuRJ3
-----END CERTIFICATE-----
```

The SAN in the certificate should match the identity that was used to
authenticate with the OAuth provider.

Using the Rekor URL displayed as part of the signing process you should also be
able to retrieve the Rekor entry for this signature:

```
$ curl --silent "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=4524464" \
  | jq --raw-output '.[].body' \
  | base64 --decode \
  | jq

{
  "apiVersion": "0.0.1",
  "kind": "hashedrekord",
  "spec": {
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "140acde551dfefbfe0b6a9b2409def68bf2decbb24384f13864399946247693c"
      }
    },
    "signature": {
      "content": "MEUCID/iVOISFCfZXEFW3IrcWXQgLDfPHRxPZBWlgDOGmXmlAiEAgi02Imw+bFQlIKeyKKpk0i60KRw7djRkA/NY6LKhI5A=",
      "publicKey": {
        "content": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvakNDQWllZ0F3SUJBZ0lVUmsxNnYyV3hXWCtYd3RtZGtVaCtHK1VJdFBvd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJeE1EQTFNakl5T0RFNVdoY05Nakl4TURBMU1qSXpPREU1V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVqZlU2SnNuaWZTVE1tUjNSVW9GbnlWRUoyUVVhcDF0bW95ZUUKQzAyZS9Od0Q5Si9CMTRqbjFRaW9wUXBIL2ZtYjJPL09mTkJjTFZZdzkvd0JFd1IyL0tPQ0FVWXdnZ0ZDTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVyczJoCnhSZ2NaQ1YwYkxtTjlxM2dKUnNuSzNFd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0h3WURWUjBSQVFIL0JCVXdFNEVSWW5KcFlXNUFaR1ZvWVcxbGNpNWpiMjB3TEFZS0t3WUJCQUdEdnpBQgpBUVFlYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJ4dloybHVMMjloZFhSb01JR0xCZ29yQmdFRUFkWjVBZ1FDCkJIMEVld0I1QUhjQUNHQ1M4Q2hTLzJoRjBkRnJKNFNjUldjWXJCWTl3empTYmVhOElnWTJiM0lBQUFHRHFrT1UKb2dBQUJBTUFTREJHQWlFQWc0c1hMa3JXNDliVWtDVVpVblNPZ1hKUGo2WU5UaWZlV0dWakRRMlM3SFVDSVFDSwpneFdMRFliV2g1eVpxWTVFUStPVFB5TlZ2SE5MUmZyUGRnZGxGUlhEdURBS0JnZ3Foa2pPUFFRREF3TnBBREJtCkFqRUF3ZG9xS2lwT2lqNGc5amVIbWZ1T1dwNUEwdFNFQk41ZkhsamF4R2dzQ3F6TWFQRm41VEhqRVZ5Rm9WNUMKUlA4NkFqRUF2dXZheVRsWW8xdkFoRXFLdzZHMnBEUXU0UnIzVEFOQXZCR1FmLytUNGI1eXJ6bThZQUJxYkZhWQpveDlPdVJKMwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
      }
    }
  }
}
```

Note that the `.spec.signature.content` value matches the signature that was
saved locally.


### Verifying

Use the `verify` command to make sure that the saved signature matches
the artifact:

```
$ ./bin/sigstore.js verify bundle.sigstore sigstore-0.0.0.tgz

Signature verified OK
```

This will use the signing certificate to ensure that the SHA256 digest
encoded in the supplied signature matches the digest of the package itself.
A future iteration of the verification logic will also find and verify
the corresponding entry in the Rekor log.

[1]: https://github.com/sigstore/rekor

## Licensing

`sigstore-js` is licensed under the Apache 2.0 License.

## Contributing

See [the contributing docs](https://github.com/sigstore/.github/blob/main/CONTRIBUTING.md) for details.

## Code of Conduct
Everyone interacting with this project is expected to follow the [sigstore Code of Conduct](https://github.com/sigstore/.github/blob/main/CODE_OF_CONDUCT.md).

## Security

Should you discover any security issues, please refer to sigstore's [security process](https://github.com/sigstore/.github/blob/main/SECURITY.md).

## Info

`sigstore-js` is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)! Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.

## Release Steps

1. Update the version inside `package.json` and run `npm i` to update `package-lock.json`.
2. PR the changes above and merge to the "main" branch when approved.
3. Use either the "[Create a new release](https://github.com/sigstore/sigstore-js/releases/new)" link or the `gh release create` CLI command to start a new release.
4. Tag the release with a label matching the version in the `package.json` (with a `v` prefix).
5. Add a title matching the tag.
6. Add release notes.
7. Mark as pre-release as appropriate.
8. Publish release.

After publishing the release, a new npm package will be built and published automatically to the npm registry.
