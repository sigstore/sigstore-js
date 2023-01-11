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
import nock from 'nock';
import { CAClient } from '../ca';
import { Signer } from '../sign';
import { TLogClient } from '../tlog';
import { HashAlgorithm } from '../types/bundle';
import { SignatureMaterial, SignerFunc } from '../types/signature';
import { pem } from '../util';

describe('Signer', () => {
  const fulcioBaseURL = 'http://localhost:8001';
  const rekorBaseURL = 'http://localhost:8002';
  const jwtPayload = {
    iss: 'https://example.com',
    sub: 'foo@bar.com',
  };
  const jwt = `.${Buffer.from(JSON.stringify(jwtPayload)).toString('base64')}.`;

  const ca = new CAClient({ fulcioBaseURL });
  const tlog = new TLogClient({ rekorBaseURL });
  const idp = { getToken: () => Promise.resolve(jwt) };

  const subject = new Signer({
    ca,
    tlog,
    identityProviders: [idp],
  });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#signBlob', () => {
    // Input
    const payload = Buffer.from('Hello, world!');

    describe('when using the default signer', () => {
      describe('when no identity provider returns a token', () => {
        const noIDTokenSubject = new Signer({
          ca,
          tlog,
          identityProviders: [],
        });

        it('throws an error', async () => {
          await expect(noIDTokenSubject.signBlob(payload)).rejects.toThrow(
            'Identity token providers failed: '
          );
        });
      });

      describe('when Fulcio returns an error', () => {
        beforeEach(() => {
          nock(fulcioBaseURL).post('/api/v1/signingCert').reply(500, {});
        });

        it('returns an error', async () => {
          await expect(subject.signBlob(payload)).rejects.toThrow(
            'HTTP Error: 500 Internal Server Error'
          );
        });
      });

      describe('when Fulcio returns successfully', () => {
        // Fulcio output
        const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----`;
        const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----`;
        const certificate = [leafCertificate, rootCertificate].join('\n');

        beforeEach(() => {
          // Mock Fulcio request
          nock(fulcioBaseURL)
            .matchHeader('Accept', 'application/pem-certificate-chain')
            .matchHeader('Content-Type', 'application/json')
            .matchHeader('Authorization', `Bearer ${jwt}`)
            .post('/api/v1/signingCert', {
              publicKey: { content: /.+/i },
              signedEmailAddress: /.+/i,
            })
            .reply(200, certificate);
        });

        describe('when Rekor returns successfully', () => {
          // Rekor output
          const signature = 'ABC123';
          const b64Cert = Buffer.from(certificate).toString('base64');
          const uuid =
            '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

          const signatureBundle = {
            kind: 'hashedrekord',
            apiVersion: '0.0.1',
            spec: {
              signature: {
                content: signature,
                publicKey: { content: b64Cert },
              },
            },
          };

          const rekorEntry = {
            [uuid]: {
              body: Buffer.from(JSON.stringify(signatureBundle)).toString(
                'base64'
              ),
              integratedTime: 1654015743,
              logID:
                'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
              logIndex: 2513258,
              verification: {
                signedEntryTimestamp:
                  'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
              },
            },
          };

          beforeEach(() => {
            // Mock Rekor request
            nock(rekorBaseURL)
              .matchHeader('Accept', 'application/json')
              .matchHeader('Content-Type', 'application/json')
              .post('/api/v1/log/entries')
              .reply(201, rekorEntry);
          });

          it('returns a signature bundle', async () => {
            const bundle = await subject.signBlob(payload);

            expect(bundle).toBeTruthy();
            expect(bundle.mediaType).toEqual(
              'application/vnd.dev.sigstore.bundle+json;version=0.1'
            );

            if (bundle.content?.$case === 'messageSignature') {
              const ms = bundle.content.messageSignature;
              expect(ms.messageDigest).toBeTruthy();
              expect(ms.messageDigest?.algorithm).toEqual(
                HashAlgorithm.SHA2_256
              );
              expect(ms.messageDigest?.digest).toBeTruthy();
              expect(ms.signature).toBeTruthy();
            } else {
              fail('Expected messageSignature');
            }

            // Verification material
            if (
              bundle.verificationMaterial?.content?.$case ===
              'x509CertificateChain'
            ) {
              const chain =
                bundle.verificationMaterial.content.x509CertificateChain;
              expect(chain).toBeTruthy();
              expect(chain.certificates).toHaveLength(2);
              expect(chain.certificates[0].rawBytes).toEqual(
                pem.toDER(leafCertificate)
              );
              expect(chain.certificates[1].rawBytes).toEqual(
                pem.toDER(rootCertificate)
              );
            } else {
              fail('Expected x509CertificateChain');
            }

            expect(
              bundle.verificationMaterial?.timestampVerificationData
            ).toBeUndefined();
            expect(bundle.verificationMaterial?.tlogEntries).toHaveLength(1);

            const tlog = bundle.verificationMaterial?.tlogEntries[0];
            expect(tlog?.inclusionPromise).toBeTruthy();
            expect(tlog?.inclusionPromise?.signedEntryTimestamp).toBeTruthy();
            expect(
              tlog?.inclusionPromise?.signedEntryTimestamp.toString('base64')
            ).toEqual(rekorEntry[uuid].verification.signedEntryTimestamp);
            expect(tlog?.integratedTime).toEqual(
              rekorEntry[uuid].integratedTime.toString()
            );
            expect(tlog?.logId).toBeTruthy();
            expect(tlog?.logId?.keyId).toBeTruthy();
            expect(tlog?.logId?.keyId.toString('hex')).toEqual(
              rekorEntry[uuid].logID
            );
            expect(tlog?.logIndex).toEqual(
              rekorEntry[uuid].logIndex.toString()
            );
            expect(tlog?.inclusionProof).toBeFalsy();
            expect(tlog?.kindVersion?.kind).toEqual('hashedrekord');
            expect(tlog?.kindVersion?.version).toEqual('0.0.1');
          });
        });

        describe('when Rekor returns an error', () => {
          beforeEach(() => {
            nock(rekorBaseURL)
              .matchHeader('Accept', 'application/json')
              .matchHeader('Content-Type', 'application/json')
              .post('/api/v1/log/entries')
              .reply(500, {});
          });

          it('returns an error', async () => {
            await expect(subject.signBlob(payload)).rejects.toThrow(
              'HTTP Error: 500 Internal Server Error'
            );
          });
        });
      });
    });

    describe('when using a custom signer', () => {
      const sigMaterial: SignatureMaterial = {
        signature: Buffer.from('ABC123'),
        certificates: undefined,
        key: {
          id: 'key-id',
          value: 'key-value',
        },
      };

      const signer = jest.fn().mockResolvedValueOnce(sigMaterial) as SignerFunc;

      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries')
          .reply(500, {});
      });

      it('invokes the custom signer', async () => {
        const s = new Signer({
          ca,
          tlog,
          identityProviders: [],
          signer,
        });

        // await expect(s.signBlob(payload)).rejects.toThrow();
        await expect(s.signBlob(payload)).rejects.toThrow();
        expect(signer).toHaveBeenCalledWith(payload);
      });
    });
  });

  describe('#signAttestation', () => {
    // Input
    const payload = Buffer.from('Hello, world!');
    const payloadType = 'text/plain';

    describe('when Fulcio returns successfully', () => {
      // Fulcio output
      const certificate = `-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----`;

      beforeEach(() => {
        // Mock Fulcio request
        nock(fulcioBaseURL)
          .matchHeader('Accept', 'application/pem-certificate-chain')
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('Authorization', `Bearer ${jwt}`)
          .post('/api/v1/signingCert', {
            publicKey: { content: /.+/i },
            signedEmailAddress: /.+/i,
          })
          .reply(200, certificate);
      });

      describe('when Rekor returns successfully', () => {
        // Rekor output
        const signature = 'ABC123';
        const b64Cert = Buffer.from(certificate).toString('base64');
        const uuid =
          '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

        const signatureBundle = {
          kind: 'intoto',
          apiVersion: '0.0.2',
          spec: {
            signature: {
              content: signature,
              publicKey: { content: b64Cert },
            },
          },
        };

        const rekorEntry = {
          [uuid]: {
            body: Buffer.from(JSON.stringify(signatureBundle)).toString(
              'base64'
            ),
            integratedTime: 1654015743,
            logID:
              'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
            logIndex: 2513258,
            verification: {
              signedEntryTimestamp:
                'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
            },
          },
        };

        beforeEach(() => {
          // Mock Rekor request
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .matchHeader('Content-Type', 'application/json')
            .post('/api/v1/log/entries')
            .reply(201, rekorEntry);
        });

        it('returns a signature bundle', async () => {
          const bundle = await subject.signAttestation(payload, payloadType);

          expect(bundle).toBeTruthy();
          expect(bundle.mediaType).toEqual(
            'application/vnd.dev.sigstore.bundle+json;version=0.1'
          );

          if (bundle.content?.$case === 'dsseEnvelope') {
            const env = bundle.content.dsseEnvelope;
            expect(env.payloadType).toEqual(payloadType);
            expect(env.payload.toString('base64')).toEqual(
              payload.toString('base64')
            );
            expect(env.signatures).toHaveLength(1);
            expect(env.signatures[0].keyid).toEqual('');
          } else {
            fail('Expected dsseEnvelope');
          }

          // Verification material
          if (
            bundle.verificationMaterial?.content?.$case ===
            'x509CertificateChain'
          ) {
            const chain =
              bundle.verificationMaterial.content.x509CertificateChain;
            expect(chain).toBeTruthy();
            expect(chain.certificates).toHaveLength(1);
            expect(chain.certificates[0].rawBytes).toEqual(
              pem.toDER(certificate)
            );
          } else {
            fail('Expected x509CertificateChain');
          }

          expect(
            bundle.verificationMaterial?.timestampVerificationData
          ).toBeUndefined();
          expect(bundle.verificationMaterial?.tlogEntries).toHaveLength(1);

          const tlog = bundle.verificationMaterial?.tlogEntries[0];
          expect(tlog?.inclusionPromise).toBeTruthy();
          expect(tlog?.inclusionPromise?.signedEntryTimestamp).toBeTruthy();
          expect(
            tlog?.inclusionPromise?.signedEntryTimestamp.toString('base64')
          ).toEqual(rekorEntry[uuid].verification.signedEntryTimestamp);
          expect(tlog?.integratedTime).toEqual(
            rekorEntry[uuid].integratedTime.toString()
          );
          expect(tlog?.logId).toBeTruthy();
          expect(tlog?.logId?.keyId).toBeTruthy();
          expect(tlog?.logId?.keyId.toString('hex')).toEqual(
            rekorEntry[uuid].logID
          );
          expect(tlog?.logIndex).toEqual(rekorEntry[uuid].logIndex.toString());
          expect(tlog?.inclusionProof).toBeFalsy();
          expect(tlog?.kindVersion?.kind).toEqual('intoto');
          expect(tlog?.kindVersion?.version).toEqual('0.0.2');
        });
      });
    });
  });
});
