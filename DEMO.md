# Demo Script

## Set-up

Start by installing `sigstore-js`:

```shell
$ npm install sigstore
```

## Signing

First generate the artifact to be signed:

```shell
$ echo "content to be signed" > artifact
```

Generate a signature for the artifact with the following:

```shell
$ npx sigstore sign artifact > bundle.sigstore

Created entry at index 12842224, available at
https://rekor.sigstore.dev/api/v1/log/entries?logIndex=12842224
```

You should see that a browser window is opened to the Sigstore OAuth page.
After authenticating with one of the available idenity providers, a signature
bundle will be generated and written to the file named "signature".

```shell
$ cat bundle.sigstore | jq

{
  "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
  "verificationMaterial": {
    "x509CertificateChain": {
      "certificates": [
        {
          "rawBytes": "MIICoDCCAiagAwIBAgIUZjkP0mPmq0ERI9O4+UkwzqcayUgwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjMwMjA3MjAyMDQ5WhcNMjMwMjA3MjAzMDQ5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOopRz43xkYXzx2p4yJlbbNilNkHeHrmnH23ax4i0jIn/wWEAt0zsRnqOgLVF1yz3jJyq6jyJDvHGv4+JQ924lqOCAUUwggFBMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUnfbpllVEqDcyeA2vzn5tX5SFBv4wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGGLYnITwAABAMARzBFAiBbkdIypZqnuZc9lSMYZ6Im5lsWprJiphdEHsN5gOkDAwIhAK75IJOx18mXlrvqXXoD/a41LGTz4kBibZOcrt6HRI/zMAoGCCqGSM49BAMDA2gAMGUCMQCpAPIPUqdBqIZB0MpcJlzYbdGWWSP61M0qe7hxjr6eDcSaaaEpBUmSgsEieLVIWC0CMDo9P4d99Gx71vIx65lGKMC5ckhwNIGzjU7LHbsd/yj2ALGmL9w37Z2GxoqE8lltwA=="
        },
        {
          "rawBytes": "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="
        },
        {
          "rawBytes": "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ"
        }
      ]
    },
    "tlogEntries": [
      {
        "logIndex": "12842224",
        "logId": {
          "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
        },
        "kindVersion": {
          "kind": "hashedrekord",
          "version": "0.0.1"
        },
        "integratedTime": "1675801250",
        "inclusionPromise": {
          "signedEntryTimestamp": "MEUCIAxR9WmdYqmuPzqEDg0cIs/WGmTCRBm0zv9g1PoqbiJgAiEAoXsW7w67mQSawMF6SvYhh5nUkI0E9aI9jp91EAu/sHk="
        },
        "canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI5YjcwYThhNDhlNzA5ZDM0OWQzNDMwNDIzMjlmN2RhNmM0NjYwNzY4YzY4NjMwOTcxY2Y1MjE5Mzk4OTc1YTM2In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUURUU3lMREFRN1Z4amRVcEs5NTBjNTRrbzEwUGh6U2tiNUowUjdtcUF0R1FBSWhBTGNIRnJCZEVCSFc2alNJQVlwR1BDeWphVVQwMU5XUjJmV0VMUWcwNDFPRSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTnZSRU5EUVdsaFowRjNTVUpCWjBsVldtcHJVREJ0VUcxeE1FVlNTVGxQTkN0VmEzZDZjV05oZVZWbmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcE5kMDFxUVROTmFrRjVUVVJSTlZkb1kwNU5hazEzVFdwQk0wMXFRWHBOUkZFMVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZQYjNCU2VqUXplR3RaV0hwNE1uQTBlVXBzWW1KT2FXeE9hMGhsU0hKdGJrZ3lNMkVLZURScE1HcEpiaTkzVjBWQmREQjZjMUp1Y1U5blRGWkdNWGw2TTJwS2VYRTJhbmxLUkhaSVIzWTBLMHBST1RJMGJIRlBRMEZWVlhkblowWkNUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZ1Wm1Kd0NteHNWa1Z4UkdONVpVRXlkbnB1TlhSWU5WTkdRblkwZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBoM1dVUldVakJTUVZGSUwwSkNWWGRGTkVWU1dXNUtjRmxYTlVGYVIxWnZXVmN4YkdOcE5XcGlNakIzVEVGWlMwdDNXVUpDUVVkRWRucEJRZ3BCVVZGbFlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVlpNamwwVERKNGRsb3liSFZNTWpsb1pGaFNiMDFKUjB0Q1oyOXlRbWRGUlVGa1dqVkJaMUZEQ2tKSWQwVmxaMEkwUVVoWlFUTlVNSGRoYzJKSVJWUktha2RTTkdOdFYyTXpRWEZLUzFoeWFtVlFTek12YURSd2VXZERPSEEzYnpSQlFVRkhSMHhaYmtrS1ZIZEJRVUpCVFVGU2VrSkdRV2xDWW10a1NYbHdXbkZ1ZFZwak9XeFRUVmxhTmtsdE5XeHpWM0J5U21sd2FHUkZTSE5PTldkUGEwUkJkMGxvUVVzM05RcEpTazk0TVRodFdHeHlkbkZZV0c5RUwyRTBNVXhIVkhvMGEwSnBZbHBQWTNKME5raFNTUzk2VFVGdlIwTkRjVWRUVFRRNVFrRk5SRUV5WjBGTlIxVkRDazFSUTNCQlVFbFFWWEZrUW5GSldrSXdUWEJqU214NldXSmtSMWRYVTFBMk1VMHdjV1UzYUhocWNqWmxSR05UWVdGaFJYQkNWVzFUWjNORmFXVk1Wa2tLVjBNd1EwMUViemxRTkdRNU9VZDROekYyU1hnMk5XeEhTMDFETldOcmFIZE9TVWQ2YWxVM1RFaGljMlF2ZVdveVFVeEhiVXc1ZHpNM1dqSkhlRzl4UlFvNGJHeDBkMEU5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19"
      }
    ]
  },
  "messageSignature": {
    "messageDigest": {
      "algorithm": "SHA2_256",
      "digest": "m3CopI5wnTSdNDBCMp99psRmB2jGhjCXHPUhk5iXWjY="
    },
    "signature": "MEYCIQDTSyLDAQ7VxjdUpK950c54ko10PhzSkb5J0R7mqAtGQAIhALcHFrBdEBHW6jSIAYpGPCyjaUT01NWR2fWELQg041OE"
  }
}
```

You'll see that the signature bundle contains the SHA256 digest of the
artifact, the signature, the signing certificate and metadata about the
entry which was made in Rekor.

You can extract and view the signing certificate with the following:
```shell
$ cat bundle.sigstore | jq --raw-output '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes' | base64 -d | openssl x509 -inform der -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            66:39:0f:d2:63:e6:ab:41:11:23:d3:b8:f9:49:30:ce:a7:1a:c9:48
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: O = sigstore.dev, CN = sigstore-intermediate
        Validity
            Not Before: Feb  7 20:20:49 2023 GMT
            Not After : Feb  7 20:30:49 2023 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:3a:8a:51:cf:8d:f1:91:85:f3:c7:6a:78:c8:99:
                    5b:6c:d8:a5:36:41:de:1e:b9:a7:1f:6d:da:c7:88:
                    b4:8c:89:ff:c1:61:00:b7:4c:ec:46:7a:8e:80:b5:
                    45:d7:2c:f7:8c:9c:aa:ea:3c:89:0e:f1:c6:bf:8f:
                    89:43:dd:b8:96
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                Code Signing
            X509v3 Subject Key Identifier: 
                9D:F6:E9:96:55:44:A8:37:32:78:0D:AF:CE:7E:6D:5F:94:85:06:FE
            X509v3 Authority Key Identifier: 
                DF:D3:E9:CF:56:24:11:96:F9:A8:D8:E9:28:55:A2:C6:2E:18:64:3F
            X509v3 Subject Alternative Name: critical
                email:foo@bar.com
            1.3.6.1.4.1.57264.1.1: 
                https://github.com/login/oauth
            CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : DD:3D:30:6A:C6:C7:11:32:63:19:1E:1C:99:67:37:02:
                                A2:4A:5E:B8:DE:3C:AD:FF:87:8A:72:80:2F:29:EE:8E
                    Timestamp : Feb  7 20:20:49.871 2023 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:20:5B:91:D2:32:A5:9A:A7:B9:97:3D:95:23:
                                18:67:A2:26:E6:5B:16:A6:B2:62:A6:17:44:1E:C3:79:
                                80:E9:03:03:02:21:00:AE:F9:20:93:B1:D7:C9:97:96:
                                BB:EA:5D:7A:03:FD:AE:35:2C:64:F3:E2:40:62:6D:93:
                                9C:AE:DE:87:44:8F:F3
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:65:02:31:00:a9:00:f2:0f:52:a7:41:a8:86:41:d0:ca:5c:
        26:5c:d8:6d:d1:96:59:23:fa:d4:cd:2a:7b:b8:71:8e:be:9e:
        0d:c4:9a:69:a1:29:05:49:92:82:c1:22:78:b5:48:58:2d:02:
        30:3a:3d:3f:87:7d:f4:6c:7b:d6:f2:31:eb:99:46:28:c0:b9:
        72:48:70:34:81:b3:8d:4e:cb:1d:bb:1d:ff:28:f6:00:b1:a6:
        2f:dc:37:ed:9d:86:c6:8a:84:f2:59:6d:c0
-----BEGIN CERTIFICATE-----
MIICoDCCAiagAwIBAgIUZjkP0mPmq0ERI9O4+UkwzqcayUgwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjMwMjA3MjAyMDQ5WhcNMjMwMjA3MjAzMDQ5WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEOopRz43xkYXzx2p4yJlbbNilNkHeHrmnH23a
x4i0jIn/wWEAt0zsRnqOgLVF1yz3jJyq6jyJDvHGv4+JQ924lqOCAUUwggFBMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUnfbp
llVEqDcyeA2vzn5tX5SFBv4wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzAB
AQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQC
BHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGGLYnI
TwAABAMARzBFAiBbkdIypZqnuZc9lSMYZ6Im5lsWprJiphdEHsN5gOkDAwIhAK75
IJOx18mXlrvqXXoD/a41LGTz4kBibZOcrt6HRI/zMAoGCCqGSM49BAMDA2gAMGUC
MQCpAPIPUqdBqIZB0MpcJlzYbdGWWSP61M0qe7hxjr6eDcSaaaEpBUmSgsEieLVI
WC0CMDo9P4d99Gx71vIx65lGKMC5ckhwNIGzjU7LHbsd/yj2ALGmL9w37Z2GxoqE
8lltwA==
-----END CERTIFICATE-----
```

The SAN in the certificate should match the identity that was used to
authenticate with the OAuth provider.

Using the Rekor URL displayed as part of the signing process you should also be
able to retrieve the Rekor entry for this signature:

```shell
$ curl --silent "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=12842224" \
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
        "value": "9b70a8a48e709d349d343042329f7da6c4660768c68630971cf5219398975a36"
      }
    },
    "signature": {
      "content": "MEYCIQDTSyLDAQ7VxjdUpK950c54ko10PhzSkb5J0R7mqAtGQAIhALcHFrBdEBHW6jSIAYpGPCyjaUT01NWR2fWELQg041OE",
      "publicKey": {
        "content": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvRENDQWlhZ0F3SUJBZ0lVWmprUDBtUG1xMEVSSTlPNCtVa3d6cWNheVVnd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpNd01qQTNNakF5TURRNVdoY05Nak13TWpBM01qQXpNRFE1V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVPb3BSejQzeGtZWHp4MnA0eUpsYmJOaWxOa0hlSHJtbkgyM2EKeDRpMGpJbi93V0VBdDB6c1JucU9nTFZGMXl6M2pKeXE2anlKRHZIR3Y0K0pROTI0bHFPQ0FVVXdnZ0ZCTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVuZmJwCmxsVkVxRGN5ZUEydnpuNXRYNVNGQnY0d0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0h3WURWUjBSQVFIL0JCVXdFNEVSWW5KcFlXNUFaR1ZvWVcxbGNpNWpiMjB3TEFZS0t3WUJCQUdEdnpBQgpBUVFlYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJ4dloybHVMMjloZFhSb01JR0tCZ29yQmdFRUFkWjVBZ1FDCkJId0VlZ0I0QUhZQTNUMHdhc2JIRVRKakdSNGNtV2MzQXFKS1hyamVQSzMvaDRweWdDOHA3bzRBQUFHR0xZbkkKVHdBQUJBTUFSekJGQWlCYmtkSXlwWnFudVpjOWxTTVlaNkltNWxzV3BySmlwaGRFSHNONWdPa0RBd0loQUs3NQpJSk94MThtWGxydnFYWG9EL2E0MUxHVHo0a0JpYlpPY3J0NkhSSS96TUFvR0NDcUdTTTQ5QkFNREEyZ0FNR1VDCk1RQ3BBUElQVXFkQnFJWkIwTXBjSmx6WWJkR1dXU1A2MU0wcWU3aHhqcjZlRGNTYWFhRXBCVW1TZ3NFaWVMVkkKV0MwQ01EbzlQNGQ5OUd4NzF2SXg2NWxHS01DNWNraHdOSUd6alU3TEhic2QveWoyQUxHbUw5dzM3WjJHeG9xRQo4bGx0d0E9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
      }
    }
  }
}
```

Note that the `.spec.signature.content` value matches the signature that was
saved locally.


## Verifying

Use the `verify` command to make sure that the saved signature matches
the artifact:

```shell
$ npx sigstore verify bundle.sigstore artifact

Signature verified OK
```

This will use the signing certificate to ensure that the SHA256 digest
encoded in the supplied signature matches the digest of the package itself.

