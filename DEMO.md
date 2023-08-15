# Demo Script

## Set-up

Start by installing the CLI:

```shell
$ npm install -g @sigstore/cli
```

## Signing

First generate the artifact to be signed:

```shell
$ echo "content to be signed" > artifact
```

Generate a signature for the artifact with the following:

```shell
$ sigstore attest artifact -o bundle.json

Created entry at index 30955468, available at
https://search.sigstore.dev?logIndex=30955468
```

You should see that a browser window is opened to the Sigstore OAuth page.
After authenticating with one of the available idenity providers, a signature
bundle will be generated and written to the file named "bundle.json".

```shell
$ cat bundle.json | jq

{
  "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
  "verificationMaterial": {
    "x509CertificateChain": {
      "certificates": [
        {
          "rawBytes": "MIIC0DCCAlagAwIBAgIUeDHfseinRdn7daK/8Z/FyZbP3bIwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjMwODExMTkxODUzWhcNMjMwODExMTkyODUzWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHxLLliGg8KvMDsipkUeQ7vn9R2MzCnJ2k3R4SHFl/JjY8Sx8hxiBQE2o91Aqz/3zlm3il3YEW19R/nyS/JmWnqOCAXUwggFxMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU/WTuM0/SvrYxbi2eNdzmeu8u9BcwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMC4GCisGAQQBg78wAQgEIAweaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGJ5gmOLAAABAMARzBFAiEA4Qda0970UObGop4NGyCF1nqV2elc8735kFIKRdH3KuoCIGIzZ5n+TMs3sC8AvJBpR07Jw/LWF8VGoXoWVWf2GGATMAoGCCqGSM49BAMDA2gAMGUCMFG0aUg0LAgFmsgbjGeKJq/7mC9gO6xBZDAU5w4ioKkE4CunWHGN93v4W6WhiieQuwIxANvAdelWupffNYMInKHNnEodhrMS/R0r7Aauv9v0RMpZU7ucKaQ3qpcL2y3e0WdZaQ=="
        }
      ]
    },
    "tlogEntries": [
      {
        "logIndex": "30955468",
        "logId": {
          "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
        },
        "kindVersion": {
          "kind": "intoto",
          "version": "0.0.2"
        },
        "integratedTime": "1691781533",
        "inclusionPromise": {
          "signedEntryTimestamp": "MEUCIA8Gl6f/EvSd+5t3v8iZOkeaP130qH48lIECNaG8G32jAiEA8BmHu8IGzaxJJiNK6Vx+tr1ZBXzsuGB3uv3dx1P7umk="
        },
        "inclusionProof": {
          "logIndex": "26792037",
          "rootHash": "cQcl3UjHWft0wEVP9BBGd+dKOcmUlaEMIYdC64mNONc=",
          "treeSize": "26792039",
          "hashes": [
            "vKGMQ1vPXwU8c5vyZgfeTPLP4FMUEpTYvXK8tiallMQ=",
            "Wb0EPMtK0MahApzam7tNvIzBUl+q7sKxT804/6NY7gI=",
            "0LvZhb2g5YcpDl5uIxDfQhGkrHGNAu9IFsRYL1XT7ec=",
            "wv1N3YOEW23a2pWHJ26ztTFU9BYAP7K5ub07HXbTVFs=",
            "NaZSOZHPk5+FIJQZ8VsBENYiUi+RauBP/COLsyk6Tro=",
            "jm0lw6HdiXlZ7GboXVWDiQvECU/hnY1hYbzrQrEoZhU=",
            "Be0XOwdJkv66MJS0dgQaI6TS+s8AL4ocQF2cFGMvhs0=",
            "9FWyBkZrudpCTcINV4W2mDTr9e7lXaqrPHlG3xrQKr4=",
            "cacw9L43sGssehTnMe+2LolJXTL9E73sEsxWjfl4DT8=",
            "umCBn5o/ndq+tuxz0bp50E/SrWnOjZXHd6tIWp+ts2s=",
            "jRUq4D8O+FI47Wbw96s7yHCu4qzWUxpIVfxQEeprDmc=",
            "rXEsmEJN4PEoTU8US4qVtdIsGB1MCiRlGOepoiC99kM="
          ],
          "checkpoint": {
            "envelope": "rekor.sigstore.dev - 2605736670972794746\n26792039\ncQcl3UjHWft0wEVP9BBGd+dKOcmUlaEMIYdC64mNONc=\nTimestamp: 1691781533798160174\n\n— rekor.sigstore.dev wNI9ajBEAiAq6zQXfHpGZ9D4aVzzCNt1vUwxQMMpnbfsC0LawPzkpwIgfDHE3XjN4N7zXG6vpN8eXDGqY30jTLojMOjHGFtySuk=\n"
          }
        },
        "canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjIiLCJraW5kIjoiaW50b3RvIiwic3BlYyI6eyJjb250ZW50Ijp7ImVudmVsb3BlIjp7InBheWxvYWRUeXBlIjoiYXBwbGljYXRpb24vdm5kLmluLXRvdG8ranNvbiIsInNpZ25hdHVyZXMiOlt7InB1YmxpY0tleSI6IkxTMHRMUzFDUlVkSlRpQkRSVkpVU1VaSlEwRlVSUzB0TFMwdENrMUpTVU13UkVORFFXeGhaMEYzU1VKQlowbFZaVVJJWm5ObGFXNVNaRzQzWkdGTEx6aGFMMFo1V21KUU0ySkpkME5uV1VsTGIxcEplbW93UlVGM1RYY0tUbnBGVmsxQ1RVZEJNVlZGUTJoTlRXTXliRzVqTTFKMlkyMVZkVnBIVmpKTlVqUjNTRUZaUkZaUlVVUkZlRlo2WVZka2VtUkhPWGxhVXpGd1ltNVNiQXBqYlRGc1drZHNhR1JIVlhkSWFHTk9UV3BOZDA5RVJYaE5WR3Q0VDBSVmVsZG9ZMDVOYWsxM1QwUkZlRTFVYTNsUFJGVjZWMnBCUVUxR2EzZEZkMWxJQ2t0dldrbDZhakJEUVZGWlNVdHZXa2w2YWpCRVFWRmpSRkZuUVVWSWVFeE1iR2xIWnpoTGRrMUVjMmx3YTFWbFVUZDJiamxTTWsxNlEyNUtNbXN6VWpRS1UwaEdiQzlLYWxrNFUzZzRhSGhwUWxGRk1tODVNVUZ4ZWk4emVteHRNMmxzTTFsRlZ6RTVVaTl1ZVZNdlNtMVhibkZQUTBGWVZYZG5aMFo0VFVFMFJ3cEJNVlZrUkhkRlFpOTNVVVZCZDBsSVowUkJWRUpuVGxaSVUxVkZSRVJCUzBKblozSkNaMFZHUWxGalJFRjZRV1JDWjA1V1NGRTBSVVpuVVZVdlYxUjFDazB3TDFOMmNsbDRZbWt5WlU1a2VtMWxkVGgxT1VKamQwaDNXVVJXVWpCcVFrSm5kMFp2UVZVek9WQndlakZaYTBWYVlqVnhUbXB3UzBaWGFYaHBORmtLV2tRNGQwaDNXVVJXVWpCU1FWRklMMEpDVlhkRk5FVlNXVzVLY0ZsWE5VRmFSMVp2V1ZjeGJHTnBOV3BpTWpCM1RFRlpTMHQzV1VKQ1FVZEVkbnBCUWdwQlVWRmxZVWhTTUdOSVRUWk1lVGx1WVZoU2IyUlhTWFZaTWpsMFRESjRkbG95YkhWTU1qbG9aRmhTYjAxRE5FZERhWE5IUVZGUlFtYzNPSGRCVVdkRkNrbEJkMlZoU0ZJd1kwaE5Oa3g1T1c1aFdGSnZaRmRKZFZreU9YUk1NbmgyV2pKc2RVd3lPV2hrV0ZKdlRVbEhTMEpuYjNKQ1owVkZRV1JhTlVGblVVTUtRa2gzUldWblFqUkJTRmxCTTFRd2QyRnpZa2hGVkVwcVIxSTBZMjFYWXpOQmNVcExXSEpxWlZCTE15OW9OSEI1WjBNNGNEZHZORUZCUVVkS05XZHRUd3BNUVVGQlFrRk5RVko2UWtaQmFVVkJORkZrWVRBNU56QlZUMkpIYjNBMFRrZDVRMFl4Ym5GV01tVnNZemczTXpWclJrbExVbVJJTTB0MWIwTkpSMGw2Q2xvMWJpdFVUWE16YzBNNFFYWktRbkJTTURkS2R5OU1WMFk0VmtkdldHOVhWbGRtTWtkSFFWUk5RVzlIUTBOeFIxTk5ORGxDUVUxRVFUSm5RVTFIVlVNS1RVWkhNR0ZWWnpCTVFXZEdiWE5uWW1wSFpVdEtjUzgzYlVNNVowODJlRUphUkVGVk5YYzBhVzlMYTBVMFEzVnVWMGhIVGpremRqUlhObGRvYVdsbFVRcDFkMGw0UVU1MlFXUmxiRmQxY0dabVRsbE5TVzVMU0U1dVJXOWthSEpOVXk5U01ISTNRV0YxZGpsMk1GSk5jRnBWTjNWalMyRlJNM0Z3WTB3eWVUTmxDakJYWkZwaFVUMDlDaTB0TFMwdFJVNUVJRU5GVWxSSlJrbERRVlJGTFMwdExTMD0iLCJzaWciOiJUVVZaUTBsUlEwTlVhMFo1VG5WcVN6RXpORGRCUkVWVVlucGlWVFpIY0VaNU9VNWtTRzFqV2poSFZuTk5PR3BEUWxGSmFFRk1lVkozT0dzMllrMWllSHAxWnpoaldHeEpiRWhrZWxJeFduZHJjamQxUlU4eE16QjBURVUwTVZKciJ9XX0sImhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIwZmU4NDVmNGRjYmYyZjMzODZlOTFlZGZlZGFiODU1YzY4ZDFhNjYyYzg2NzIzZWEwZTM0NjY4YTNjZDliNTA1In0sInBheWxvYWRIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiOWI3MGE4YTQ4ZTcwOWQzNDlkMzQzMDQyMzI5ZjdkYTZjNDY2MDc2OGM2ODYzMDk3MWNmNTIxOTM5ODk3NWEzNiJ9fX19"
      }
    ],
    "timestampVerificationData": {
      "rfc3161Timestamps": []
    }
  },
  "dsseEnvelope": {
    "payload": "Y29udGVudCB0byBiZSBzaWduZWQK",
    "payloadType": "application/vnd.in-toto+json",
    "signatures": [
      {
        "sig": "MEYCIQCCTkFyNujK1347ADETbzbU6GpFy9NdHmcZ8GVsM8jCBQIhALyRw8k6bMbxzug8cXlIlHdzR1Zwkr7uEO130tLE41Rk",
        "keyid": ""
      }
    ]
  }
}
```

You'll see that the signature bundle contains the base64-encoded version of
the artifact, the generated signature, the signing certificate and metadata 
about the entry which was made in Rekor.

You can extract and view the signing certificate with the following:
```shell
$ cat bundle.json | jq --raw-output '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes' | base64 -d | openssl x509 -inform der -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            78:31:df:b1:e8:a7:45:d9:fb:75:a2:bf:f1:9f:c5:c9:96:cf:dd:b2
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: O = sigstore.dev, CN = sigstore-intermediate
        Validity
            Not Before: Aug 11 19:18:53 2023 GMT
            Not After : Aug 11 19:28:53 2023 GMT
        Subject: 
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:1f:12:cb:96:21:a0:f0:ab:cc:0e:c8:a9:91:47:
                    90:ee:f9:fd:47:63:33:0a:72:76:93:74:78:48:71:
                    65:fc:98:d8:f1:2c:7c:87:18:81:40:4d:a8:f7:50:
                    2a:cf:fd:f3:96:6d:e2:97:76:04:5b:5f:51:fe:7c:
                    92:fc:99:96:9e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                Code Signing
            X509v3 Subject Key Identifier: 
                FD:64:EE:33:4F:D2:BE:B6:31:6E:2D:9E:35:DC:E6:7A:EF:2E:F4:17
            X509v3 Authority Key Identifier: 
                DF:D3:E9:CF:56:24:11:96:F9:A8:D8:E9:28:55:A2:C6:2E:18:64:3F
            X509v3 Subject Alternative Name: critical
                email:foo@bar.com
            1.3.6.1.4.1.57264.1.1: 
                https://github.com/login/oauth
            1.3.6.1.4.1.57264.1.8: 
                ..https://github.com/login/oauth
            CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : DD:3D:30:6A:C6:C7:11:32:63:19:1E:1C:99:67:37:02:
                                A2:4A:5E:B8:DE:3C:AD:FF:87:8A:72:80:2F:29:EE:8E
                    Timestamp : Aug 11 19:18:53.228 2023 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:21:00:E1:07:5A:D3:DE:F4:50:E6:C6:A2:9E:
                                0D:1B:20:85:D6:7A:95:D9:E9:5C:F3:BD:F9:90:52:0A:
                                45:D1:F7:2A:EA:02:20:62:33:67:99:FE:4C:CB:37:B0:
                                2F:00:BC:90:69:47:4E:C9:C3:F2:D6:17:C5:46:A1:7A:
                                16:55:67:F6:18:60:13
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:65:02:30:51:b4:69:48:34:2c:08:05:9a:c8:1b:8c:67:8a:
        26:af:fb:98:2f:60:3b:ac:41:64:30:14:e7:0e:22:a0:a9:04:
        e0:2b:a7:58:71:8d:f7:7b:f8:5b:a5:a1:8a:27:90:bb:02:31:
        00:db:c0:75:e9:56:ba:97:df:35:83:08:9c:a1:cd:9c:4a:1d:
        86:b3:12:fd:1d:2b:ec:06:ae:bf:db:f4:44:ca:59:53:bb:9c:
        29:a4:37:aa:97:0b:db:2d:de:d1:67:59:69
-----BEGIN CERTIFICATE-----
MIIC0DCCAlagAwIBAgIUeDHfseinRdn7daK/8Z/FyZbP3bIwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjMwODExMTkxODUzWhcNMjMwODExMTkyODUzWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEHxLLliGg8KvMDsipkUeQ7vn9R2MzCnJ2k3R4
SHFl/JjY8Sx8hxiBQE2o91Aqz/3zlm3il3YEW19R/nyS/JmWnqOCAXUwggFxMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU/WTu
M0/SvrYxbi2eNdzmeu8u9BcwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzAB
AQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMC4GCisGAQQBg78wAQgE
IAweaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQC
BHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGJ5gmO
LAAABAMARzBFAiEA4Qda0970UObGop4NGyCF1nqV2elc8735kFIKRdH3KuoCIGIz
Z5n+TMs3sC8AvJBpR07Jw/LWF8VGoXoWVWf2GGATMAoGCCqGSM49BAMDA2gAMGUC
MFG0aUg0LAgFmsgbjGeKJq/7mC9gO6xBZDAU5w4ioKkE4CunWHGN93v4W6WhiieQ
uwIxANvAdelWupffNYMInKHNnEodhrMS/R0r7Aauv9v0RMpZU7ucKaQ3qpcL2y3e
0WdZaQ==
-----END CERTIFICATE-----
```

The SAN in the certificate should match the identity that was used to
authenticate with the OAuth provider.

Using the Rekor URL displayed as part of the signing process you should also be
able to retrieve the Rekor entry for this signature:

```shell
$ curl --silent "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=30955468" \
  | jq --raw-output '.[].body' \
  | base64 --decode \
  | jq

{
  "apiVersion": "0.0.2",
  "kind": "intoto",
  "spec": {
    "content": {
      "envelope": {
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [
          {
            "publicKey": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMwRENDQWxhZ0F3SUJBZ0lVZURIZnNlaW5SZG43ZGFLLzhaL0Z5WmJQM2JJd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpNd09ERXhNVGt4T0RVeldoY05Nak13T0RFeE1Ua3lPRFV6V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVIeExMbGlHZzhLdk1Ec2lwa1VlUTd2bjlSMk16Q25KMmszUjQKU0hGbC9Kalk4U3g4aHhpQlFFMm85MUFxei8zemxtM2lsM1lFVzE5Ui9ueVMvSm1XbnFPQ0FYVXdnZ0Z4TUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVUvV1R1Ck0wL1N2cll4YmkyZU5kem1ldTh1OUJjd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0h3WURWUjBSQVFIL0JCVXdFNEVSWW5KcFlXNUFaR1ZvWVcxbGNpNWpiMjB3TEFZS0t3WUJCQUdEdnpBQgpBUVFlYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJ4dloybHVMMjloZFhSb01DNEdDaXNHQVFRQmc3OHdBUWdFCklBd2VhSFIwY0hNNkx5OW5hWFJvZFdJdVkyOXRMMnh2WjJsdUwyOWhkWFJvTUlHS0Jnb3JCZ0VFQWRaNUFnUUMKQkh3RWVnQjRBSFlBM1Qwd2FzYkhFVEpqR1I0Y21XYzNBcUpLWHJqZVBLMy9oNHB5Z0M4cDdvNEFBQUdKNWdtTwpMQUFBQkFNQVJ6QkZBaUVBNFFkYTA5NzBVT2JHb3A0Tkd5Q0YxbnFWMmVsYzg3MzVrRklLUmRIM0t1b0NJR0l6Clo1bitUTXMzc0M4QXZKQnBSMDdKdy9MV0Y4VkdvWG9XVldmMkdHQVRNQW9HQ0NxR1NNNDlCQU1EQTJnQU1HVUMKTUZHMGFVZzBMQWdGbXNnYmpHZUtKcS83bUM5Z082eEJaREFVNXc0aW9La0U0Q3VuV0hHTjkzdjRXNldoaWllUQp1d0l4QU52QWRlbFd1cGZmTllNSW5LSE5uRW9kaHJNUy9SMHI3QWF1djl2MFJNcFpVN3VjS2FRM3FwY0wyeTNlCjBXZFphUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=",
            "sig": "TUVZQ0lRQ0NUa0Z5TnVqSzEzNDdBREVUYnpiVTZHcEZ5OU5kSG1jWjhHVnNNOGpDQlFJaEFMeVJ3OGs2Yk1ieHp1ZzhjWGxJbEhkelIxWndrcjd1RU8xMzB0TEU0MVJr"
          }
        ]
      },
      "hash": {
        "algorithm": "sha256",
        "value": "0fe845f4dcbf2f3386e91edfedab855c68d1a662c86723ea0e34668a3cd9b505"
      },
      "payloadHash": {
        "algorithm": "sha256",
        "value": "9b70a8a48e709d349d343042329f7da6c4660768c68630971cf5219398975a36"
      }
    }
  }
}
```

Note that the `.spec.content.envelope.signatures[0].sig` value matches the signature that was
saved to the generated bundle.


## Verifying

Use the `verify` command to make sure that the saved signature matches
the artifact:

```shell
$ igstore verify bundle.sigstore

Verification succeeded
```

