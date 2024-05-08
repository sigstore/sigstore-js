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
import { Rekor } from '../../external/rekor';

import type { ProposedHashedRekordEntry } from '../../external/rekor';

describe('Rekor', () => {
  const baseURL = 'http://localhost:8080';
  const subject = new Rekor({ baseURL });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#createEntry', () => {
    const proposedEntry: ProposedHashedRekordEntry = {
      apiVersion: '0.0.1',
      kind: 'hashedrekord',
      spec: {
        data: {
          hash: {
            algorithm: 'sha256',
            value:
              '1c025a6e48ceb8bf10e01b367089732326eabe3541d03d348724c79040382c65',
          },
        },
        signature: {
          content:
            'MEUCIDB2SWDabztSC8RrlfRCWUf04LBN0E2CEwiDZJLacDS8AiEA3bQHMBpodxA3dvJ+JK1SALkuzju/w4oCg3S89c8CtN8=',
          publicKey: {
            content:
              'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K',
          },
        },
      },
    };
    const uuid =
      '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';
    const responseBody = {
      [uuid]: {
        body: 'Zm9vCg==',
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

    describe('when the entry is successfully added', () => {
      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('User-Agent', new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'))
          .post('/api/v1/log/entries')
          .reply(201, responseBody);
      });

      it('returns the new entry', async () => {
        const result = await subject.createEntry(proposedEntry);

        expect(result.uuid).toBe(uuid);
        expect(result.body).toBe(responseBody[uuid].body);
        expect(result.integratedTime).toBe(responseBody[uuid].integratedTime);
        expect(result.logID).toBe(responseBody[uuid].logID);
        expect(result.logIndex).toBe(responseBody[uuid].logIndex);
        expect(result.verification).toEqual(responseBody[uuid].verification);
      });
    });

    describe('when a matching entry already exists', () => {
      const responseBody = {
        code: 409,
        message: 'An equivalent entry already exists',
      };

      beforeEach(() => {
        nock(baseURL).post('/api/v1/log/entries').reply(409, responseBody);
      });

      it('returns an error', async () => {
        await expect(subject.createEntry(proposedEntry)).rejects.toThrow(
          '(409) An equivalent entry already exists'
        );
      });
    });

    describe('when the entry is successfully added after retry', () => {
      let scope: nock.Scope;

      beforeEach(() => {
        scope = nock(baseURL)
          .post('/api/v1/log/entries')
          .reply(500)
          .post('/api/v1/log/entries')
          .reply(201, responseBody);
      });

      it('returns the new entry', async () => {
        const subject = new Rekor({
          baseURL,
          retry: { retries: 1, factor: 0, minTimeout: 1, maxTimeout: 1 },
        });
        const result = await subject.createEntry(proposedEntry);

        expect(result.uuid).toBe(uuid);
        expect(result.body).toBe(responseBody[uuid].body);
        expect(result.integratedTime).toBe(responseBody[uuid].integratedTime);
        expect(result.logID).toBe(responseBody[uuid].logID);
        expect(result.logIndex).toBe(responseBody[uuid].logIndex);
        expect(result.verification).toEqual(responseBody[uuid].verification);
        expect(scope.isDone()).toBe(true);
      });
    });
  });

  describe('#getEntry', () => {
    const uuid =
      '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';
    const responseBody = {
      [uuid]: {
        body: 'Zm9vCg==',
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

    describe('when the entry exists', () => {
      beforeEach(() => {
        nock(baseURL)
          .get(`/api/v1/log/entries/${uuid}`)
          .reply(200, responseBody);
      });

      it('returns the requested entry', async () => {
        const result = await subject.getEntry(uuid);

        expect(result.uuid).toBe(uuid);
        expect(result.body).toBe(responseBody[uuid].body);
        expect(result.integratedTime).toBe(responseBody[uuid].integratedTime);
        expect(result.logID).toBe(responseBody[uuid].logID);
        expect(result.logIndex).toBe(responseBody[uuid].logIndex);
        expect(result.verification).toEqual(responseBody[uuid].verification);
      });
    });

    describe('when the entry does not exist', () => {
      const responseBody = {
        code: 404,
        message: 'Entry not found',
      };

      beforeEach(() => {
        nock(baseURL).get('/api/v1/log/entries/foo').reply(404, responseBody);
      });

      it('returns an error', async () => {
        await expect(subject.getEntry('foo')).rejects.toThrow(
          '(404) Entry not found'
        );
      });
    });

    describe('when there are multiple entries in the response', () => {
      const uuid =
        '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';
      const responseBody = {
        [uuid]: { body: 'foo' },
        '456': { body: 'bar' },
      };

      beforeEach(() => {
        nock(baseURL)
          .get(`/api/v1/log/entries/${uuid}`)
          .reply(200, responseBody);
      });

      it('returns an error', async () => {
        await expect(subject.getEntry(uuid)).rejects.toThrow(
          'Received multiple entries in Rekor response'
        );
      });
    });

    describe('when the entry is successfully retrieved after retry', () => {
      let scope: nock.Scope;

      beforeEach(() => {
        scope = nock(baseURL)
          .get(`/api/v1/log/entries/${uuid}`)
          .reply(500)
          .get(`/api/v1/log/entries/${uuid}`)
          .reply(200, responseBody);
      });

      it('returns the requested entry', async () => {
        const subject = new Rekor({
          baseURL,
          retry: { retries: 1, factor: 0, minTimeout: 1, maxTimeout: 1 },
        });
        const result = await subject.getEntry(uuid);

        expect(result.uuid).toBe(uuid);
        expect(result.body).toBe(responseBody[uuid].body);
        expect(result.integratedTime).toBe(responseBody[uuid].integratedTime);
        expect(result.logID).toBe(responseBody[uuid].logID);
        expect(result.logIndex).toBe(responseBody[uuid].logIndex);
        expect(result.verification).toEqual(responseBody[uuid].verification);
        expect(scope.isDone()).toBe(true);
      });
    });
  });
});
