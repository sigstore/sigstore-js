/*
Copyright 2022 The Sigstore Authors.

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
import { createPublicKey } from 'crypto';
import { VerificationError } from './error';
import { TLogClient } from './tlog';
import { Bundle, Envelope, HashAlgorithm } from './types/bundle';
import { crypto } from './util';
import { Verifier } from './verify';

describe('Verifier', () => {
  const rekorBaseURL = 'http://localhost:8002';
  const tlog = new TLogClient({ rekorBaseURL });

  const tlogKey = createPublicKey(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`);

  const keys = { abc: tlogKey };
  const subject = new Verifier({ tlog, tlogKeys: keys });

  describe('#verify', () => {
    describe('when bundle type is messageSignature', () => {
      const payload = Buffer.from('Hello, world!');

      const signature = Buffer.from(
        'MEUCIFRsQUBCo06j+lKpCx2XaaVS0N+f6czW8aBsgek5aeoZAiEA/A2KUxPCvxFjFu184a1256IGVmiFfZagq5Pm0yUgQLU=',
        'base64'
      );
      // Cert that could have generated the signature above
      const signingCert = Buffer.from(
        'MIICuDCCAj2gAwIBAgIUVetSMQzfTmukM9CJut++Hwp/Y8swCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjIwNjA4MTcwMzEyWhcNMjIwNjA4MTcxMzEyWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtOcykILDEST3p7bdgn3262KZVIyG/AvH9zdmQWC1yiGkUWfjUQyh+VI5lzQ2AqquTwBQXd7Bp4ehQpc4XiZjA6OCAVwwggFYMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUJZ/1diLHD43ouHgyhkrqzBtELkwwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wOQYDVR0RAQH/BC8wLYErYXJ0c2lnbmVyQGRlaGFtZXIyNC5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbTApBgorBgEEAYO/MAEBBBtodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20wgYoGCisGAQQB1nkCBAIEfAR6AHgAdgAIYJLwKFL/aEXR0WsnhJxFZxisFj3DONJt5rwiBjZvcgAAAYFERSjMAAAEAwBHMEUCIQDQaCKbXmNpjX11IUagh6NCmkliDpGzAMwDcLZXv3UGrwIgcos4fjGTb8aDoca6OE8J04BVbJ5W0u8srSQc1zl7awAwCgYIKoZIzj0EAwMDaQAwZgIxAJDFW8lbCUHO/T3oFvMW7YxXBPVus6R97LacCxhOslzXYAa1wmZK4UygLvEKzHLDugIxAPiFR6EkAEkBbBsCd8iMqgttFjuAZADkZ1bLgZSUOHErV5/0ind1ZHkMrq5drCxZoQ==',
        'base64'
      );

      const bundle: Bundle = {
        mediaType: 'application/vnd.in-toto+json',
        content: {
          $case: 'messageSignature',
          messageSignature: {
            signature: signature,
            messageDigest: {
              algorithm: HashAlgorithm.SHA2_256,
              digest: crypto.hash(payload),
            },
          },
        },
        verificationMaterial: {
          content: {
            $case: 'x509CertificateChain',
            x509CertificateChain: {
              certificates: [{ derBytes: signingCert }],
            },
          },
        },
        verificationData: {
          timestampVerificationData: {
            rfc3161Timestamps: [],
          },
          tlogEntries: [],
        },
      };

      describe('when the signature and the cert match', () => {
        it('returns true', async () => {
          await expect(subject.verify(bundle, payload)).resolves.toBe(
            undefined
          );
        });
      });

      describe('when the signature and the cert do NOT match', () => {
        it('returns false', async () => {
          await expect(subject.verify(bundle, Buffer.from(''))).rejects.toThrow(
            VerificationError
          );
        });
      });
    });

    describe('when bundle type is dsseEnvelope', () => {
      const payload = Buffer.from('hello world');
      const payloadType = 'text/plain';
      const signature = Buffer.from(
        'MEQCICI87pUJwMdF/AuTxb+i9OFWvzIOoxEnJx0oEqayXEBzAiAzjiZJ3FvcGINs+5oZrZNh36g3GKAnv6Ssr+J9eOGHHg==',
        'base64'
      );

      // Cert that could have generated the signature above
      const signingCert = Buffer.from(
        'MIICojCCAiegAwIBAgIUI0HZwtebunssZNhomqJGvF5W5r0wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjIwODE5MTc1MDU5WhcNMjIwODE5MTgwMDU5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0Ae1SXbXvI7e+cO65yLGi7zM+GTt49eI7dzP4JAc/JDuXbNtOszGw2t3Lsdv7kv5fxa6vGu0363tIv6QxAZ7Y6OCAUYwggFCMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU3Pv0p3PGqubvL796mDiTIRSyClgwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGLBgorBgEEAdZ5AgQCBH0EewB5AHcACGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3IAAAGCtzrH+AAABAMASDBGAiEAiyilyKylomkyLFhkHaJ28PnkCHCtkDcdCuQTuQ188u4CIQDjTLwkwSCtGKPl4KpMMxwbJNS5qp/O/aGqU/OouLkDLTAKBggqhkjOPQQDAwNpADBmAjEA9Qi8FK/46W++OFaGTWTjEBT5FkD9pLgNfkMNew5sVn2iQyA2fI2F93MJJvrLlNG+AjEA/boyyIyBIjd/Nc4shZiJUmtBKIN8eRYekAES5BIkHs++WuSLTP8AAUPeOOuC3sG/',
        'base64'
      );

      const envelope: Envelope = {
        payload: payload,
        payloadType,
        signatures: [{ keyid: '', sig: signature }],
      };

      const bundle: Bundle = {
        mediaType: 'application/vnd.dev.cosign.simplesigning.v1+json',
        content: {
          $case: 'dsseEnvelope',
          dsseEnvelope: envelope,
        },
        verificationMaterial: {
          content: {
            $case: 'x509CertificateChain',
            x509CertificateChain: {
              certificates: [{ derBytes: signingCert }],
            },
          },
        },
        verificationData: {
          tlogEntries: [],
          timestampVerificationData: {
            rfc3161Timestamps: [],
          },
        },
      };

      describe('when the signature and the cert match', () => {
        it('returns true', async () => {
          await expect(subject.verify(bundle)).resolves.toBe(undefined);
        });
      });

      describe('when the signature and the cert do NOT match', () => {
        it('returns false', async () => {
          const invalidBundle = { ...bundle };
          if (invalidBundle.content?.$case === 'dsseEnvelope') {
            invalidBundle.content.dsseEnvelope.payloadType = 'invalid';
          }

          await expect(subject.verify(invalidBundle)).rejects.toThrow(
            VerificationError
          );
        });
      });
    });
  });
});
