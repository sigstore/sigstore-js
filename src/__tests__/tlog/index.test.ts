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
import {
  toProposedHashedRekordEntry,
  toProposedIntotoEntry,
} from '../../tlog/format';
import { TLogClient } from '../../tlog/index';
import { SignatureMaterial } from '../../types/signature';
import { Envelope, HashAlgorithm } from '../../types/sigstore';
import { pem } from '../../util';

describe('TLogClient', () => {
  const baseURL = 'http://localhost:8080';

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new TLogClient({ rekorBaseURL: baseURL });
      expect(client).toBeDefined();
    });
  });

  describe('createMessageSignatureEntry', () => {
    const subject = new TLogClient({ rekorBaseURL: baseURL });

    const digest = Buffer.from('digest');

    const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----`;
    const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----`;

    const sigMaterial: SignatureMaterial = {
      signature: Buffer.from('signature'),
      certificates: [leafCertificate, rootCertificate],
      key: undefined,
    };

    // Rekor input
    const proposedEntry = JSON.stringify(
      toProposedHashedRekordEntry(digest, sigMaterial)
    );

    describe('when Rekor returns an error', () => {
      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries', proposedEntry)
          .reply(500, {});
      });

      it('returns an error', async () => {
        await expect(
          subject.createMessageSignatureEntry(digest, sigMaterial)
        ).rejects.toThrow('HTTP Error: 500 Internal Server Error');
      });
    });

    describe('when Rekor returns a valid response', () => {
      // Rekor output
      const b64Cert = Buffer.from(leafCertificate).toString('base64');
      const uuid =
        '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

      const signatureBundle = {
        kind: 'hashedrekord',
        apiVersion: '0.0.1',
        spec: {
          signature: {
            content: sigMaterial.signature.toString('hex'),
            publicKey: { content: b64Cert },
          },
        },
      };

      const rekorEntry = {
        [uuid]: {
          body: Buffer.from(JSON.stringify(signatureBundle)).toString('base64'),
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
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries', proposedEntry)
          .reply(201, rekorEntry);
      });

      it('returns a signature bundle', async () => {
        const bundle = await subject.createMessageSignatureEntry(
          digest,
          sigMaterial
        );

        expect(bundle).toBeTruthy();
        expect(bundle.mediaType).toEqual(
          'application/vnd.dev.sigstore.bundle+json;version=0.1'
        );

        if (bundle.content?.$case === 'messageSignature') {
          const ms = bundle.content.messageSignature;
          expect(ms.messageDigest).toBeTruthy();
          expect(ms.messageDigest?.algorithm).toEqual(HashAlgorithm.SHA2_256);
          expect(ms.messageDigest?.digest).toBeTruthy();
          expect(ms.signature).toBeTruthy();
        } else {
          fail('Expected messageSignature');
        }

        // Verification material
        if (
          bundle.verificationMaterial?.content?.$case === 'x509CertificateChain'
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
        expect(tlog?.logIndex).toEqual(rekorEntry[uuid].logIndex.toString());
        expect(tlog?.inclusionProof).toBeFalsy();
        expect(tlog?.kindVersion?.kind).toEqual('hashedrekord');
        expect(tlog?.kindVersion?.version).toEqual('0.0.1');
      });
    });
  });

  describe('createDSSEEntry', () => {
    const subject = new TLogClient({ rekorBaseURL: baseURL });

    // Input
    const payload = Buffer.from('Hello, world!');
    const payloadType = 'text/plain';
    const signature = Buffer.from('signature');

    const dsse: Envelope = {
      payload,
      payloadType,
      signatures: [{ keyid: '', sig: signature }],
    };
    const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----`;
    const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----`;

    const sigMaterial: SignatureMaterial = {
      signature,
      certificates: [leafCertificate, rootCertificate],
      key: undefined,
    };

    // Rekor input
    const proposedEntry = JSON.stringify(
      toProposedIntotoEntry(dsse, sigMaterial)
    );

    describe('when Rekor returns a 500 error', () => {
      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries', proposedEntry)
          .reply(500, {});
      });

      it('returns an error', async () => {
        await expect(
          subject.createDSSEEntry(dsse, sigMaterial)
        ).rejects.toThrow('HTTP Error: 500 Internal Server Error');
      });
    });

    describe('when Rekor returns a 409 conflict error', () => {
      const uuid =
        '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries', proposedEntry)
          .reply(409, {}, { Location: `/api/v1/log/entries/${uuid}` });
      });

      describe('when fetchOnConflict is false', () => {
        it('returns an error', async () => {
          await expect(
            subject.createDSSEEntry(dsse, sigMaterial, {
              fetchOnConflict: false,
            })
          ).rejects.toThrow('HTTP Error: 409 Conflict');
        });
      });

      describe('when fetchOnConflict is true', () => {
        const signatureBundle = {
          kind: 'intoto',
          apiVersion: '0.0.2',
          spec: {
            signature: {
              content: signature,
              publicKey: { content: leafCertificate },
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
          nock(baseURL)
            .get(`/api/v1/log/entries/${uuid}`)
            .reply(200, rekorEntry);
        });

        it('returns a signature bundle', async () => {
          const bundle = await subject.createDSSEEntry(dsse, sigMaterial, {
            fetchOnConflict: true,
          });
          expect(bundle).toBeTruthy();
          expect(bundle.mediaType).toEqual(
            'application/vnd.dev.sigstore.bundle+json;version=0.1'
          );
        });
      });
    });

    describe('when Rekor returns a valid response', () => {
      const uuid =
        '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

      const signatureBundle = {
        kind: 'intoto',
        apiVersion: '0.0.2',
        spec: {
          signature: {
            content: signature,
            publicKey: { content: leafCertificate },
          },
        },
      };

      const rekorEntry = {
        [uuid]: {
          body: Buffer.from(JSON.stringify(signatureBundle)).toString('base64'),
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
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries', proposedEntry)
          .reply(201, rekorEntry);
      });

      it('returns a signature bundle', async () => {
        const bundle = await subject.createDSSEEntry(dsse, sigMaterial);

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
          bundle.verificationMaterial?.content?.$case === 'x509CertificateChain'
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
        expect(tlog?.logIndex).toEqual(rekorEntry[uuid].logIndex.toString());
        expect(tlog?.inclusionProof).toBeFalsy();
        expect(tlog?.kindVersion?.kind).toEqual('intoto');
        expect(tlog?.kindVersion?.version).toEqual('0.0.2');
      });
    });
  });
});
