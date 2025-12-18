/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { TrustedRoot } from '@sigstore/protobuf-specs';

const trustedRootJSON = {
  mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
  tlogs: [
    {
      baseUrl: 'https://tlog.sigstore.dev',
      hashAlgorithm: 'SHA2_256',
      publicKey: {
        rawBytes:
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
        keyDetails: 'PKIX_ECDSA_P256_SHA_256',
      },
      logId: {
        keyId: 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=',
      },
    },
    {
      baseUrl: 'https://log2025-1.rekor.sigstore.dev',
      hashAlgorithm: 'SHA2_256',
      publicKey: {
        rawBytes:
          'MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=',
        keyDetails: 'PKIX_ED25519',
        validFor: {
          start: '2025-09-23T00:00:00Z',
        },
      },
      logId: {
        keyId: 'zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=',
      },
    },
  ],
  certificateAuthorities: [
    {
      subject: {
        organization: 'sigstore.dev',
        commonName: 'sigstore',
      },
      uri: 'https://fulcio.sigstore.dev',
      certChain: {
        certificates: [
          {
            rawBytes:
              'MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ==',
          },
        ],
      },
      validFor: {
        start: undefined,
        end: undefined,
      },
    },
    {
      subject: {
        organization: 'sigstore.dev',
        commonName: 'sigstore',
      },
      uri: 'https://fulcio.sigstore.dev',
      certChain: {
        certificates: [
          {
            rawBytes:
              'MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ',
          },
          {
            rawBytes:
              'MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=',
          },
        ],
      },
      validFor: {
        start: '2022-04-13T20:06:15.000Z',
        end: '2031-10-05T13:56:58.000Z',
      },
    },
  ],
  ctlogs: [
    {
      baseUrl: 'https://ctfe.sigstage.dev/test',
      hashAlgorithm: 'SHA2_256',
      publicKey: {
        rawBytes:
          'MIICCgKCAgEA27A2MPQXm0I0v7/Ly5BIauDjRZF5Jor9vU+QheoE2UIIsZHcyYq3slHzSSHy2lLj1ZD2d91CtJ492ZXqnBmsr4TwZ9jQ05tW2mGIRI8u2DqN8LpuNYZGz/f9SZrjhQQmUttqWmtu3UoLfKz6NbNXUnoo+NhZFcFRLXJ8VporVhuiAmL7zqT53cXR3yQfFPCUDeGnRksnlhVIAJc3AHZZSHQJ8DEXMhh35TVv2nYhTI3rID7GwjXXw4ocz7RGDD37ky6p39Tl5NB71gT1eSqhZhGHEYHIPXraEBd5+3w9qIuLWlp5Ej/K6Mu4ELioXKCUimCbwy+Cs8UhHFlqcyg4AysOHJwIadXIa8LsY51jnVSGrGOEBZevopmQPNPtyfFY3dmXSS+6Z3RD2Gd6oDnNGJzpSyEk410Ag5uvNDfYzJLCWX9tU8lIxNwdFYmIwpd89HijyRyoGnoJ3entd63cvKfuuix5r+GHyKp1Xm1L5j5AWM6P+z0xigwkiXnt+adexAl1J9wdDxv/pUFEESRF4DG8DFGVtbdH6aR1A5/vD4krO4tC1QYUSeyL5Mvsw8WRqIFHcXtgybtxylljvNcGMV1KXQC8UFDmpGZVDSHx6v3e/BHMrZ7gjoCCfVMZ/cFcQi0W2AIHPYEMH/C95J2r4XbHMRdYXpovpOoT5Ca78gsCAwEAAQ==',
        keyDetails: 'PKCS1_RSA_PKCS1V5',
        validFor: {
          start: '2021-03-14T00:00:00.000Z',
          end: '2022-07-31T00:00:00.000Z',
        },
      },
      logId: {
        keyId: 'G3wUKk6ZK6ffHh/FdCRUE2wVekyzHEEIpSG4savnv0w=',
      },
    },
    {
      baseUrl: 'https://ctfe.sigstore.dev/test',
      hashAlgorithm: 'SHA2_256',
      publicKey: {
        rawBytes:
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==',
        keyDetails: 'PKIX_ECDSA_P256_SHA_256',
      },
      logId: {
        keyId: 'CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I=',
      },
    },
    {
      baseUrl: 'https://ctfe.sigstore.dev/2022',
      hashAlgorithm: 'SHA2_256',
      publicKey: {
        rawBytes:
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==',
        keyDetails: 'PKIX_ECDSA_P256_SHA_256',
      },
      logId: {
        keyId: '3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4=',
      },
    },
  ],
  timestampAuthorities: [
    {
      subject: {
        organization: '',
        commonName: '',
      },
      uri: 'http://localhost:8080',
      certChain: {
        certificates: [
          {
            rawBytes:
              'MIIBuzCCAWGgAwIBAgIBAjAKBggqhkjOPQQDAzAmMQwwCgYDVQQDEwN0c2ExFjAUBgNVBAoTDXNpZ3N0b3JlLm1vY2swHhcNMjIwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAuMRQwEgYDVQQDEwt0c2Egc2lnbmluZzEWMBQGA1UEChMNc2lnc3RvcmUubW9jazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGCOIXjk6za2Ttu3pRRPMp363TzIpLbUZG3vrySkOdBum38EN1soS6UcMMKIXpQwJvMUcyeep2LCGt1R4r1b6ZijeDB2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMB0GA1UdDgQWBBQ/FFxk7FUxt/oE8lDZEF0s7kasuDAfBgNVHSMEGDAWgBQ/FFxk7FUxt/oE8lDZEF0s7kasuDAKBggqhkjOPQQDAwNIADBFAiEArRcIu8babXmdnuGaW6qlH/kEg4GFvbme1VT0tc3o1I4CIHpMdIm3GVBdc2ac0NmQRo3EDXJIdsFdcAAKbG0vFEwZ',
          },
          {
            rawBytes:
              'MIIBnTCCAUSgAwIBAgIBATAKBggqhkjOPQQDAzAmMQwwCgYDVQQDEwN0c2ExFjAUBgNVBAoTDXNpZ3N0b3JlLm1vY2swHhcNMjIwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAmMQwwCgYDVQQDEwN0c2ExFjAUBgNVBAoTDXNpZ3N0b3JlLm1vY2swWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARgjiF45Os2tk7bt6UUTzKd+t08yKS21GRt768kpDnQbpt/BDdbKEulHDDCiF6UMCbzFHMnnqdiwhrdUeK9W+mYo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUPxRcZOxVMbf6BPJQ2RBdLO5GrLgwHwYDVR0jBBgwFoAUPxRcZOxVMbf6BPJQ2RBdLO5GrLgwCgYIKoZIzj0EAwMDRwAwRAIgeIGv1zfVElTGrpX6rofi6blEa70mVQXyoKxkXf49+E8CIBtsrSwDbmGUMhjAF5kxaLThEsBCZHRKi+BKcZ4sJlBE',
          },
        ],
      },
      validFor: {
        start: undefined,
        end: undefined,
      },
    },
    {
      subject: {
        organization: 'sigstore.dev',
        commonName: 'sigstore-tsa-selfsigned',
      },
      uri: 'https://timestamp.sigstore.dev/api/v1/timestamp',
      certChain: {
        certificates: [
          {
            rawBytes:
              'MIICEDCCAZagAwIBAgIUOhNULwyQYe68wUMvy4qOiyojiwwwCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMC4xFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEVMBMGA1UEAxMMc2lnc3RvcmUtdHNhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4ra2Z8hKNig2T9kFjCAToGG30jky+WQv3BzL+mKvh1SKNR/UwuwsfNCg4sryoYAd8E6isovVA3M4aoNdm9QDi50Z8nTEyvqgfDPtTIwXItfiW/AFf1V7uwkbkAoj0xxco2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFIn9eUOHz9BlRsMCRscsc1t9tOsDMB8GA1UdIwQYMBaAFJjsAe9/u1H/1JUeb4qImFMHic6/MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMDA2gAMGUCMDtpsV/6KaO0qyF/UMsX2aSUXKQFdoGTptQGc0ftq1csulHPGG6dsmyMNd3JB+G3EQIxAOajvBcjpJmKb4Nv+2Taoj8Uc5+b6ih6FXCCKraSqupe07zqswMcXJTe1cExvHvvlw==',
          },
          {
            rawBytes:
              'MIIB9zCCAXygAwIBAgIUV7f0GLDOoEzIh8LXSW80OJiUp14wCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMDkxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEgMB4GA1UEAxMXc2lnc3RvcmUtdHNhLXNlbGZzaWduZWQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQUQNtfRT/ou3YATa6wB/kKTe70cfJwyRIBovMnt8RcJph/COE82uyS6FmppLLL1VBPGcPfpQPYJNXzWwi8icwhKQ6W/Qe2h3oebBb2FHpwNJDqo+TMaC/tdfkv/ElJB72jRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSY7AHvf7tR/9SVHm+KiJhTB4nOvzAKBggqhkjOPQQDAwNpADBmAjEAwGEGrfGZR1cen1R8/DTVMI943LssZmJRtDp/i7SfGHmGRP6gRbuj9vOK3b67Z0QQAjEAuT2H673LQEaHTcyQSZrkp4mX7WwkmF+sVbkYY5mXN+RMH13KUEHHOqASaemYWK/E',
          },
        ],
      },
      validFor: {
        start: '2025-07-04T00:00:00Z',
      },
    },
  ],
};

export const trustedRoot = TrustedRoot.fromJSON(trustedRootJSON);
