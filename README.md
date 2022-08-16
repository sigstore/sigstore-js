# sigstore-js

**This project is not ready for general-purpose use!**

A tool for signing and verifying npm packages.

## Features

* Support for signing npm packages using an OpenID Connect identity
* Support for publishing signatures to a [Rekor][1] instance
* Support for verifying signatures on npm packages

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
$ ./bin/sigstore.js sign ./sigstore-0.0.0.tgz > signature

Created entry at index 2698234, available at
https://rekor.sigstore.dev/api/v1/log/entries/43553c769cd0bd99aee4350d2e78ca3fb015840a2f6f4cf31b475f588fc214e6
```

You should see that a browser window is opened to the Sigstore OAuth page.
After authenticating with one of the available idenity providers, a signature
bundle will be generated and written to the file named "signature".

```
$ cat signature | jq

{
  "attestationType": "attestation/blob",
  "attestation": {
    "payloadHash": "3ad055f2b0d850290fbe0ce63f8c60adf492901c5950ac01e0893ebb47bea4d8",
    "payloadHashAlgorithm": "sha256",
    "signature": "MEUCIQC7Rrrjmrwdxuc2qvWiWzaoUdV8+VFv+fvDquvAGmxr3AIgaPEqQ5YvxjfeqgXYXvISzgyVA8y/Zw+G/LDYlt2RHMk="
  },
  "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvakNDQWllZ0F3SUJBZ0lVQkswdTBRdWF3dkVJWm82YS9keGVzbEthZU9jd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09ERTJNVFEwTVRJd1doY05Nakl3T0RFMk1UUTFNVEl3V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVFRWlrR2hsMXdzSzFLMStSYTBQRU9SQzh5SXE4bTBWM0VXSSsKbDIrY2w3aUFyM0xrc292Nk5qUmtyc3VjUVVpMmRmSi9uUlZlYi9rREw1WTJYbS9VTGFPQ0FVWXdnZ0ZDTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVnNUtlCk9JWnRvRktnd3ZKVjZSSHB6M2hWcTFjd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0h3WURWUjBSQVFIL0JCVXdFNEVSWW5KcFlXNUFaR1ZvWVcxbGNpNWpiMjB3TEFZS0t3WUJCQUdEdnpBQgpBUVFlYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJ4dloybHVMMjloZFhSb01JR0xCZ29yQmdFRUFkWjVBZ1FDCkJIMEVld0I1QUhjQUNHQ1M4Q2hTLzJoRjBkRnJKNFNjUldjWXJCWTl3empTYmVhOElnWTJiM0lBQUFHQ3B4b1YKNVFBQUJBTUFTREJHQWlFQWtSZ1kxczlQajNFbjI1d3o0aHpXbEQzeStBYXVBSmRXd2tvWFdUZmlYd2NDSVFEMgo2a1JBU1BPbzBhdDIzNy9zTVVrd1YvSEhEQ0lBNkVnZzl2eG1pUEJqbURBS0JnZ3Foa2pPUFFRREF3TnBBREJtCkFqRUF6eDBYU3hMSkdKT29OWjN6Zk02RkUxbUZZZ3daQUJIRTFBb2xFd3ZYdTdZNUdFMkU2RWxzVjRHVDR2YlkKd2FOVUFqRUFqZzhaZlA3WXR0L1RIOVBXV1hqYkhpR3laamlpMHFpVVpTZGthTVJseGx0aC9QNXpGaHdkRTN2cQpoL1Z0UUNCdwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDR2pDQ0FhR2dBd0lCQWdJVUFMblZpVmZuVTBickphc21Sa0hybi9VbmZhUXdDZ1lJS29aSXpqMEVBd013CktqRVZNQk1HQTFVRUNoTU1jMmxuYzNSdmNtVXVaR1YyTVJFd0R3WURWUVFERXdoemFXZHpkRzl5WlRBZUZ3MHkKTWpBME1UTXlNREEyTVRWYUZ3MHpNVEV3TURVeE16VTJOVGhhTURjeEZUQVRCZ05WQkFvVERITnBaM04wYjNKbApMbVJsZGpFZU1Cd0dBMVVFQXhNVmMybG5jM1J2Y21VdGFXNTBaWEp0WldScFlYUmxNSFl3RUFZSEtvWkl6ajBDCkFRWUZLNEVFQUNJRFlnQUU4UlZTL3lzSCtOT3Z1RFp5UEladGlsZ1VGOU5sYXJZcEFkOUhQMXZCQkgxVTVDVjcKN0xTUzdzMFppSDRuRTdIdjdwdFM2THZ2Ui9TVGs3OThMVmdNekxsSjRIZUlmRjN0SFNhZXhMY1lwU0FTcjFrUwowTi9SZ0JKei85aldDaVhubzNzd2VUQU9CZ05WSFE4QkFmOEVCQU1DQVFZd0V3WURWUjBsQkF3d0NnWUlLd1lCCkJRVUhBd013RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBZEJnTlZIUTRFRmdRVTM5UHB6MVlrRVpiNXFOanAKS0ZXaXhpNFlaRDh3SHdZRFZSMGpCQmd3Rm9BVVdNQWVYNUZGcFdhcGVzeVFvWk1pMENyRnhmb3dDZ1lJS29aSQp6ajBFQXdNRFp3QXdaQUl3UENzUUs0RFlpWllEUElhRGk1SEZLbmZ4WHg2QVNTVm1FUmZzeW5ZQmlYMlg2U0pSCm5aVTg0LzlEWmRuRnZ2eG1BakJPdDZRcEJsYzRKLzBEeHZrVENxcGNsdnppTDZCQ0NQbmpkbElCM1B1M0J4c1AKbXlnVVk3SWkyemJkQ2RsaWlvdz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQjl6Q0NBWHlnQXdJQkFnSVVBTFpOQVBGZHhIUHdqZURsb0R3eVlDaEFPLzR3Q2dZSUtvWkl6ajBFQXdNdwpLakVWTUJNR0ExVUVDaE1NYzJsbmMzUnZjbVV1WkdWMk1SRXdEd1lEVlFRREV3aHphV2R6ZEc5eVpUQWVGdzB5Ck1URXdNRGN4TXpVMk5UbGFGdzB6TVRFd01EVXhNelUyTlRoYU1Db3hGVEFUQmdOVkJBb1RESE5wWjNOMGIzSmwKTG1SbGRqRVJNQThHQTFVRUF4TUljMmxuYzNSdmNtVXdkakFRQmdjcWhrak9QUUlCQmdVcmdRUUFJZ05pQUFUNwpYZUZUNHJiM1BRR3dTNElhanRMazMvT2xucGdhbmdhQmNsWXBzWUJyNWkrNHluQjA3Y2ViM0xQME9JT1pkeGV4Clg2OWM1aVZ1eUpSUStIejA1eWkrVUYzdUJXQWxIcGlTNXNoMCtIMkdIRTdTWHJrMUVDNW0xVHIxOUw5Z2c5MmoKWXpCaE1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJSWQp3QjVma1VXbFpxbDZ6SkNoa3lMUUtzWEYrakFmQmdOVkhTTUVHREFXZ0JSWXdCNWZrVVdsWnFsNnpKQ2hreUxRCktzWEYrakFLQmdncWhrak9QUVFEQXdOcEFEQm1BakVBajFuSGVYWnArMTNOV0JOYStFRHNEUDhHMVdXZzF0Q00KV1AvV0hQcXBhVm8wamhzd2VORlpnU3MwZUU3d1lJNHFBakVBMldCOW90OThzSWtvRjN2WllkZDMvVnRXQjViOQpUTk1lYTdJeC9zdEo1VGZjTExlQUJMRTRCTkpPc1E0dm5CSEoKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==",
  "signedEntryTimestamp": "MEUCIQDLVDIXVubRBoS6tXXWptNEQNUuwPpnflrd93uBCsm3QAIgPZA5pyWhPpv9hftq0dk8b7ipjNCBzM5yIaSVXyokXbU=",
  "integratedTime": 1655485921,
  "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
  "logIndex": 2698234
}
```

You'll see that the signature bundle contains the SHA256 digest of the
artifact, the signature, the signing certificate and metadata about the
entry which was made in Rekor.

You can extract and view the signing certificate with the following:
```
$ cat signature | jq --raw-output '.certificate' | base64 -d | openssl x509 -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1a:8a:25:49:b9:86:46:1e:4a:4f:70:e8:5c:20:52:03:e6:04:ee:7b
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: O = sigstore.dev, CN = sigstore-intermediate
        Validity
            Not Before: Jun 17 17:12:01 2022 GMT
            Not After : Jun 17 17:22:01 2022 GMT
        Subject:
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:77:55:0b:20:32:67:bb:a1:eb:9a:da:18:a7:11:
                    30:d8:b2:0b:50:90:9f:7c:ef:31:8c:c3:09:4d:b4:
                    17:6d:f2:ed:d4:36:90:15:8e:a1:21:35:aa:88:03:
                    09:16:fb:07:f8:25:a1:6b:ae:47:db:df:08:a0:c3:
                    42:3a:43:14:eb
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                Code Signing
            X509v3 Subject Key Identifier:
                AD:4D:65:B1:5D:18:6C:E7:DA:E6:79:04:F3:83:DB:B0:AA:D8:C6:FF
            X509v3 Authority Key Identifier:
                DF:D3:E9:CF:56:24:11:96:F9:A8:D8:E9:28:55:A2:C6:2E:18:64:3F
            X509v3 Subject Alternative Name: critical
                email:foo@bar.com
            1.3.6.1.4.1.57264.1.1:
                https://github.com/login/oauth
            CT Precertificate SCTs:
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 08:60:92:F0:28:52:FF:68:45:D1:D1:6B:27:84:9C:45:
                                67:18:AC:16:3D:C3:38:D2:6D:E6:BC:22:06:36:6F:72
                    Timestamp : Jun 17 17:12:01.084 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:20:27:19:2F:A7:20:53:8D:27:92:AC:F8:08:
                                73:DC:F9:DB:9C:B7:1C:3C:77:90:C0:6E:CC:CA:1D:8A:
                                79:55:4E:05:02:21:00:FF:70:1D:86:F1:7C:CB:A2:B2:
                                ED:F5:16:0B:0D:C9:A1:7D:97:7A:31:62:DC:1B:3F:E9:
                                E2:6B:EE:11:9C:20:2B
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:65:02:30:30:d3:7c:0e:fc:6f:0f:8e:35:4c:ae:f6:5d:37:
        51:da:1d:36:a7:33:ba:ab:5f:1f:e1:80:fa:1c:7f:b2:44:6c:
        cd:4e:e0:21:ec:91:de:01:95:60:17:be:88:c8:8f:9c:02:31:
        00:ee:d6:c6:23:ff:b6:6c:66:65:82:9f:9b:ca:f0:ed:cc:4d:
        63:5d:70:58:b4:c2:1e:55:8f:21:b3:d7:27:16:6d:cb:22:0a:
        92:37:d6:61:38:ff:bc:43:69:eb:28:9d:af
-----BEGIN CERTIFICATE-----
MIICoDCCAiagAwIBAgIUGoolSbmGRh5KT3DoXCBSA+YE7nswCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjIwNjE3MTcxMjAxWhcNMjIwNjE3MTcyMjAxWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEd1ULIDJnu6HrmtoYpxEw2LILUJCffO8xjMMJ
TbQXbfLt1DaQFY6hITWqiAMJFvsH+CWha65H298IoMNCOkMU66OCAUUwggFBMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUrU1l
sV0YbOfa5nkE84PbsKrYxv8wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzAB
AQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQC
BHwEegB4AHYACGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3IAAAGBcqZ3
PAAABAMARzBFAiAnGS+nIFONJ5Ks+Ahz3PnbnLccPHeQwG7Myh2KeVVOBQIhAP9w
HYbxfMuisu31FgsNyaF9l3oxYtwbP+nia+4RnCArMAoGCCqGSM49BAMDA2gAMGUC
MDDTfA78bw+ONUyu9l03UdodNqczuqtfH+GA+hx/skRszU7gIeyR3gGVYBe+iMiP
nAIxAO7WxiP/tmxmZYKfm8rw7cxNY11wWLTCHlWPIbPXJxZtyyIKkjfWYTj/vENp
6yidrw==
-----END CERTIFICATE-----
```

The SAN in the certificate should match the identity that was used to
authenticate with the OAuth provider.

Using the Rekor URL displayed as part of the signing process you should also be
able to retrieve the Rekor entry for this signature:

```
$ curl --silent https://rekor.sigstore.dev/api/v1/log/entries/43553c769cd0bd99aee4350d2e78ca3fb015840a2f6f4cf31b475f588fc214e6 \
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
        "value": "3ad055f2b0d850290fbe0ce63f8c60adf492901c5950ac01e0893ebb47bea4d8"
      }
    },
    "signature": {
      "content": "MEUCIQC7Rrrjmrwdxuc2qvWiWzaoUdV8+VFv+fvDquvAGmxr3AIgaPEqQ5YvxjfeqgXYXvISzgyVA8y/Zw+G/LDYlt2RHMk=",
      "publicKey": {
        "content": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvRENDQWlhZ0F3SUJBZ0lVR29vbFNibUdSaDVLVDNEb1hDQlNBK1lFN25zd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd05qRTNNVGN4TWpBeFdoY05Nakl3TmpFM01UY3lNakF4V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVkMVVMSURKbnU2SHJtdG9ZcHhFdzJMSUxVSkNmZk84eGpNTUoKVGJRWGJmTHQxRGFRRlk2aElUV3FpQU1KRnZzSCtDV2hhNjVIMjk4SW9NTkNPa01VNjZPQ0FVVXdnZ0ZCTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVyVTFsCnNWMFliT2ZhNW5rRTg0UGJzS3JZeHY4d0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0h3WURWUjBSQVFIL0JCVXdFNEVSWW5KcFlXNUFaR1ZvWVcxbGNpNWpiMjB3TEFZS0t3WUJCQUdEdnpBQgpBUVFlYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJ4dloybHVMMjloZFhSb01JR0tCZ29yQmdFRUFkWjVBZ1FDCkJId0VlZ0I0QUhZQUNHQ1M4Q2hTLzJoRjBkRnJKNFNjUldjWXJCWTl3empTYmVhOElnWTJiM0lBQUFHQmNxWjMKUEFBQUJBTUFSekJGQWlBbkdTK25JRk9OSjVLcytBaHozUG5ibkxjY1BIZVF3RzdNeWgyS2VWVk9CUUloQVA5dwpIWWJ4Zk11aXN1MzFGZ3NOeWFGOWwzb3hZdHdiUCtuaWErNFJuQ0FyTUFvR0NDcUdTTTQ5QkFNREEyZ0FNR1VDCk1ERFRmQTc4YncrT05VeXU5bDAzVWRvZE5xY3p1cXRmSCtHQStoeC9za1JzelU3Z0lleVIzZ0dWWUJlK2lNaVAKbkFJeEFPN1d4aVAvdG14bVpZS2ZtOHJ3N2N4TlkxMXdXTFRDSGxXUEliUFhKeFp0eXlJS2tqZldZVGovdkVOcAo2eWlkcnc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDR2pDQ0FhR2dBd0lCQWdJVUFMblZpVmZuVTBickphc21Sa0hybi9VbmZhUXdDZ1lJS29aSXpqMEVBd013CktqRVZNQk1HQTFVRUNoTU1jMmxuYzNSdmNtVXVaR1YyTVJFd0R3WURWUVFERXdoemFXZHpkRzl5WlRBZUZ3MHkKTWpBME1UTXlNREEyTVRWYUZ3MHpNVEV3TURVeE16VTJOVGhhTURjeEZUQVRCZ05WQkFvVERITnBaM04wYjNKbApMbVJsZGpFZU1Cd0dBMVVFQXhNVmMybG5jM1J2Y21VdGFXNTBaWEp0WldScFlYUmxNSFl3RUFZSEtvWkl6ajBDCkFRWUZLNEVFQUNJRFlnQUU4UlZTL3lzSCtOT3Z1RFp5UEladGlsZ1VGOU5sYXJZcEFkOUhQMXZCQkgxVTVDVjcKN0xTUzdzMFppSDRuRTdIdjdwdFM2THZ2Ui9TVGs3OThMVmdNekxsSjRIZUlmRjN0SFNhZXhMY1lwU0FTcjFrUwowTi9SZ0JKei85aldDaVhubzNzd2VUQU9CZ05WSFE4QkFmOEVCQU1DQVFZd0V3WURWUjBsQkF3d0NnWUlLd1lCCkJRVUhBd013RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBZEJnTlZIUTRFRmdRVTM5UHB6MVlrRVpiNXFOanAKS0ZXaXhpNFlaRDh3SHdZRFZSMGpCQmd3Rm9BVVdNQWVYNUZGcFdhcGVzeVFvWk1pMENyRnhmb3dDZ1lJS29aSQp6ajBFQXdNRFp3QXdaQUl3UENzUUs0RFlpWllEUElhRGk1SEZLbmZ4WHg2QVNTVm1FUmZzeW5ZQmlYMlg2U0pSCm5aVTg0LzlEWmRuRnZ2eG1BakJPdDZRcEJsYzRKLzBEeHZrVENxcGNsdnppTDZCQ0NQbmpkbElCM1B1M0J4c1AKbXlnVVk3SWkyemJkQ2RsaWlvdz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQjl6Q0NBWHlnQXdJQkFnSVVBTFpOQVBGZHhIUHdqZURsb0R3eVlDaEFPLzR3Q2dZSUtvWkl6ajBFQXdNdwpLakVWTUJNR0ExVUVDaE1NYzJsbmMzUnZjbVV1WkdWMk1SRXdEd1lEVlFRREV3aHphV2R6ZEc5eVpUQWVGdzB5Ck1URXdNRGN4TXpVMk5UbGFGdzB6TVRFd01EVXhNelUyTlRoYU1Db3hGVEFUQmdOVkJBb1RESE5wWjNOMGIzSmwKTG1SbGRqRVJNQThHQTFVRUF4TUljMmxuYzNSdmNtVXdkakFRQmdjcWhrak9QUUlCQmdVcmdRUUFJZ05pQUFUNwpYZUZUNHJiM1BRR3dTNElhanRMazMvT2xucGdhbmdhQmNsWXBzWUJyNWkrNHluQjA3Y2ViM0xQME9JT1pkeGV4Clg2OWM1aVZ1eUpSUStIejA1eWkrVUYzdUJXQWxIcGlTNXNoMCtIMkdIRTdTWHJrMUVDNW0xVHIxOUw5Z2c5MmoKWXpCaE1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJSWQp3QjVma1VXbFpxbDZ6SkNoa3lMUUtzWEYrakFmQmdOVkhTTUVHREFXZ0JSWXdCNWZrVVdsWnFsNnpKQ2hreUxRCktzWEYrakFLQmdncWhrak9QUVFEQXdOcEFEQm1BakVBajFuSGVYWnArMTNOV0JOYStFRHNEUDhHMVdXZzF0Q00KV1AvV0hQcXBhVm8wamhzd2VORlpnU3MwZUU3d1lJNHFBakVBMldCOW90OThzSWtvRjN2WllkZDMvVnRXQjViOQpUTk1lYTdJeC9zdEo1VGZjTExlQUJMRTRCTkpPc1E0dm5CSEoKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
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
$ ./bin/sigstore.js verify sigstore-0.0.0.tgz signature signingcert.pem

Signature verified OK
```

This will use the signing certificate to ensure that the SHA256 digest
encoded in the supplied signature matches the digest of the package itself.
A future iteration of the verification logic will also find and verify
the corresponding entry in the Rekor log.

[1]: https://github.com/sigstore/rekor
