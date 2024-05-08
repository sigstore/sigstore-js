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
import nock from 'nock';
import { InternalError } from '../../../error';
import { ProposedEntry, TLogClient } from '../../../witness/tlog/client';

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
