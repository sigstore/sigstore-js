/*
Copyright 2025 The Sigstore Authors.

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
import { InternalError } from '../../../error';
import {
  ProposedEntry,
  TLogClient,
  TLogV2Client,
} from '../../../witness/tlog/client';

import type { CreateEntryRequest } from '@sigstore/protobuf-specs/rekor/v2';
import assert from 'assert';

describe('TLogClient', () => {
  const rekorBaseURL = 'http://localhost:8080';

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new TLogClient({ rekorBaseURL });
      expect(client).toBeDefined();
    });
  });

  describe('createEntry', () => {
    const subject = new TLogClient({ rekorBaseURL, retry: false });

    const digest = Buffer.from('digest').toString('hex');
    const signature = Buffer.from('signature').toString('base64');
    const publicKey = Buffer.from('publicKey').toString('base64');

    const proposedEntry = {
      apiVersion: '0.0.1',
      kind: 'hashedrekord',
      spec: {
        data: {
          hash: {
            algorithm: 'sha256',
            value: digest,
          },
        },
        signature: {
          content: signature,
          publicKey: {
            content: publicKey,
          },
        },
      },
    } satisfies ProposedEntry;

    const uuid =
      '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

    const rekorEntry = {
      [uuid]: {
        body: Buffer.from(JSON.stringify(proposedEntry)).toString('base64'),
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

    describe('when Rekor returns an error', () => {
      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries', proposedEntry)
          .reply(500, {});
      });

      it('returns an error', async () => {
        await expect(
          subject.createEntry(proposedEntry)
        ).rejects.toThrowWithCode(InternalError, 'TLOG_CREATE_ENTRY_ERROR');
      });
    });

    describe('when Rekor returns a valid response', () => {
      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries', proposedEntry)
          .reply(201, rekorEntry);
      });

      it('returns a tlog entry', async () => {
        const entry = await subject.createEntry(proposedEntry);

        expect(entry.uuid).toEqual(uuid);
        expect(entry.logID).toEqual(rekorEntry[uuid].logID);
        expect(entry.logIndex).toEqual(rekorEntry[uuid].logIndex);
        expect(entry.integratedTime).toEqual(rekorEntry[uuid].integratedTime);
        expect(entry?.verification?.signedEntryTimestamp).toEqual(
          rekorEntry[uuid].verification.signedEntryTimestamp
        );
        expect(entry.body).toEqual(rekorEntry[uuid].body);
      });
    });

    describe('when Rekor returns a 409 conflict error', () => {
      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries', proposedEntry)
          .reply(409, {}, { Location: `/api/v1/log/entries/${uuid}` });
      });

      describe('when fetchOnConflict is false', () => {
        const subject = new TLogClient({
          rekorBaseURL,
          fetchOnConflict: false,
        });

        it('returns an error', async () => {
          await expect(
            subject.createEntry(proposedEntry)
          ).rejects.toThrowWithCode(InternalError, 'TLOG_CREATE_ENTRY_ERROR');
        });
      });

      describe('when fetchOnConflict is true', () => {
        const subject = new TLogClient({ rekorBaseURL, fetchOnConflict: true });

        describe('when the fetch is successful', () => {
          beforeEach(() => {
            nock(rekorBaseURL)
              .get(`/api/v1/log/entries/${uuid}`)
              .reply(200, rekorEntry);
          });

          it('returns a tlog entry', async () => {
            const entry = await subject.createEntry(proposedEntry);
            expect(entry).toBeTruthy();
          });
        });

        describe('when the fetch returns an error', () => {
          beforeEach(() => {
            nock(rekorBaseURL)
              .get(`/api/v1/log/entries/${uuid}`)
              .reply(404, {});
          });

          it('returns an error', async () => {
            await expect(
              subject.createEntry(proposedEntry)
            ).rejects.toThrowWithCode(InternalError, 'TLOG_FETCH_ENTRY_ERROR');
          });
        });
      });
    });

    describe('when Rekor returns a valid response after retry', () => {
      let scope: nock.Scope;

      beforeEach(() => {
        scope = nock(rekorBaseURL)
          .post('/api/v1/log/entries')
          .reply(500, { message: 'oops' })
          .post('/api/v1/log/entries')
          .reply(201, rekorEntry);
      });

      it('returns a tlog entry', async () => {
        const subject = new TLogClient({
          rekorBaseURL,
          retry: { retries: 1, factor: 0, minTimeout: 1, maxTimeout: 1 },
        });
        const entry = await subject.createEntry(proposedEntry);

        expect(entry.uuid).toEqual(uuid);
        expect(entry.logID).toEqual(rekorEntry[uuid].logID);
        expect(entry.logIndex).toEqual(rekorEntry[uuid].logIndex);
        expect(entry.integratedTime).toEqual(rekorEntry[uuid].integratedTime);
        expect(entry?.verification?.signedEntryTimestamp).toEqual(
          rekorEntry[uuid].verification.signedEntryTimestamp
        );
        expect(entry.body).toEqual(rekorEntry[uuid].body);
        expect(scope.isDone()).toBe(true);
      });
    });
  });
});

describe('TLogV2Client', () => {
  const rekorBaseURL = 'http://localhost:8080';

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new TLogV2Client({ rekorBaseURL });
      expect(client).toBeDefined();
    });
  });

  describe('createEntry', () => {
    const subject = new TLogV2Client({ rekorBaseURL, retry: false });

    const createEntryRequest: CreateEntryRequest = {
      spec: {
        $case: 'hashedRekordRequestV002',
        hashedRekordRequestV002: {
          digest: Buffer.from('digest'),
          signature: {
            content: Buffer.from('signature'),
            verifier: {
              keyDetails: 5, // PKIX_ECDSA_P256_SHA_256
              verifier: {
                $case: 'x509Certificate',
                x509Certificate: {
                  rawBytes: Buffer.from('certificate'),
                },
              },
            },
          },
        },
      },
    };

    const rekorEntry = {
      logIndex: '2513258',
      logId: {
        keyId: 'zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A=',
      },
      kindVersion: {
        kind: 'hashedrekord',
        version: '0.0.2',
      },
      integratedTime: '0',
      inclusionPromise: null,
      inclusionProof: {
        logIndex: '2513258',
        rootHash: '+8vUkEgBK/ansexBUomzocaWoPEmPIzxJC/y+xNMQN4=',
        treeSize: '412115',
        hashes: [
          'KIoYVJ0TqmaEkFboP7YWTjSh8vFjVECmokcTOAByfIM=',
          'Umf0h0cK2hegTzNnSgsXszyiA4bp5OvEvP+GrWq3C8w=',
          'vNQeSNBfepYZI2Ez3ViKdCft0JH87ZS8IGKwixxUVjc=',
          'JBAugd5awOqmHXIKgz1MOjlR5f37VqmP0bWoRVcHX5M=',
          'xYH2mAxGxfOgvSOLnItT2LsJt+Z2a2egjf8QJFwK7jA=',
          'PbZWM3NitzChx9A22m/kddDtzh2bAKX5Fy7j76l3z2k=',
          'sKX9Sbsahvw5DiC2oP6pbZsDi1NzuNS1nIULXkCC57o=',
          'pfTCxXHnCM253jwYxVJcuUhmoTTtDxznn92QhN0M4Ws=',
          'cJ8uk2ZvZyfg+HRILKOHcyHu2pvI8Fz3R1MyMvyzWtA=',
        ],
        checkpoint: {
          envelope:
            'log2025-1.rekor.sigstore.dev\n412115\n+8vUkEgBK/ansexBUomzocaWoPEmPIzxJC/y+xNMQN4=\n\n— log2025-1.rekor.sigstore.dev zxGZFahCZ/+MqTjH4rC5MWcdLDWbpetE5l30RZfQc4BQkRjWSoKipEUPjvHENeZDHIlAsuezJcLzUVvItpNjaSRoMAs=\n',
        },
      },
      canonicalizedBody: Buffer.from(
        JSON.stringify(createEntryRequest)
      ).toString('base64'),
    };

    describe('when Rekor returns an error', () => {
      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v2/log/entries')
          .reply(500, {});
      });

      it('returns an error', async () => {
        await expect(
          subject.createEntry(createEntryRequest)
        ).rejects.toThrowWithCode(InternalError, 'TLOG_CREATE_ENTRY_ERROR');
      });
    });

    describe('when Rekor returns a valid response', () => {
      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v2/log/entries')
          .reply(201, rekorEntry);
      });

      it('returns a tlog entry', async () => {
        const entry = await subject.createEntry(createEntryRequest);

        expect(entry.logIndex).toEqual(rekorEntry.logIndex);
        expect(entry.logId.keyId).toEqual(
          Buffer.from(rekorEntry.logId.keyId, 'base64')
        );
        expect(entry.integratedTime).toEqual(rekorEntry.integratedTime);
        expect(entry.kindVersion).toEqual(rekorEntry.kindVersion);
        expect(entry.inclusionPromise).toBeUndefined();
        assert(entry.inclusionProof);
        expect(entry.inclusionProof.logIndex).toEqual(
          rekorEntry.inclusionProof.logIndex
        );
        expect(entry.inclusionProof.rootHash).toEqual(
          Buffer.from(rekorEntry.inclusionProof.rootHash, 'base64')
        );
        expect(entry.inclusionProof.treeSize).toEqual(
          rekorEntry.inclusionProof.treeSize
        );
        expect(entry.inclusionProof.hashes).toEqual(
          rekorEntry.inclusionProof.hashes.map((h: string) =>
            Buffer.from(h, 'base64')
          )
        );
        assert(entry.inclusionProof.checkpoint);
        expect(entry.inclusionProof.checkpoint.envelope).toEqual(
          rekorEntry.inclusionProof.checkpoint.envelope
        );
        expect(entry.canonicalizedBody).toEqual(
          Buffer.from(rekorEntry.canonicalizedBody, 'base64')
        );
      });
    });

    describe('when Rekor returns an incomplete response', () => {
      describe('when logId is missing', () => {
        const incompleteEntry = {
          ...rekorEntry,
          logId: undefined,
        };

        beforeEach(() => {
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .matchHeader('Content-Type', 'application/json')
            .post('/api/v2/log/entries')
            .reply(201, incompleteEntry);
        });

        it('returns an error', async () => {
          await expect(
            subject.createEntry(createEntryRequest)
          ).rejects.toThrowWithCode(InternalError, 'TLOG_CREATE_ENTRY_ERROR');
        });
      });

      describe('when kindVersion is missing', () => {
        const incompleteEntry = {
          ...rekorEntry,
          kindVersion: undefined,
        };

        beforeEach(() => {
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .matchHeader('Content-Type', 'application/json')
            .post('/api/v2/log/entries')
            .reply(201, incompleteEntry);
        });

        it('returns an error', async () => {
          await expect(
            subject.createEntry(createEntryRequest)
          ).rejects.toThrowWithCode(InternalError, 'TLOG_CREATE_ENTRY_ERROR');
        });
      });
    });

    describe('when Rekor returns a valid response after retry', () => {
      let scope: nock.Scope;

      beforeEach(() => {
        scope = nock(rekorBaseURL)
          .post('/api/v2/log/entries')
          .reply(500, { message: 'oops' })
          .post('/api/v2/log/entries')
          .reply(201, rekorEntry);
      });

      it('returns a tlog entry', async () => {
        const subject = new TLogV2Client({
          rekorBaseURL,
          retry: { retries: 1, factor: 0, minTimeout: 1, maxTimeout: 1 },
        });
        const entry = await subject.createEntry(createEntryRequest);

        expect(entry.logIndex).toEqual(rekorEntry.logIndex);
      });
    });
  });
});
