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
import { HashedRekordKind, Rekor } from './rekor';

describe('Rekor', () => {
  const baseURL = 'http://localhost:8080';
  const subject = new Rekor({ baseURL });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#createEntry', () => {
    const proposedEntry: HashedRekordKind = {
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

    describe('when the entry is successfully added', () => {
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
          'HTTP Error: 409 Conflict'
        );
      });
    });
  });

  describe('#createHashedRekordEntry', () => {
    const artifactDigest =
      '1c025a6e48ceb8bf10e01b367089732326eabe3541d03d348724c79040382c65';
    const artifactSignature =
      'MEUCIDB2SWDabztSC8RrlfRCWUf04LBN0E2CEwiDZJLacDS8AiEA3bQHMBpodxA3dvJ+JK1SALkuzju/w4oCg3S89c8CtN8=';
    const publicKey =
      'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K';

    const proposedEntry = {
      apiVersion: '0.0.1',
      kind: 'hashedrekord',
      spec: {
        data: {
          hash: {
            algorithm: 'sha256',
            value: artifactDigest,
          },
        },
        signature: {
          content: artifactSignature,
          publicKey: {
            content: publicKey,
          },
        },
      },
    };

    const uuid =
      '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';
    const responseBody = {
      [uuid]: {},
    };

    beforeEach(() => {
      nock(baseURL)
        .matchHeader('Accept', 'application/json')
        .matchHeader('Content-Type', 'application/json')
        .post('/api/v1/log/entries', proposedEntry)
        .reply(201, responseBody);
    });

    it('submits a new hashedrekor entry', async () => {
      const result = await subject.createHashedRekordEntry({
        artifactDigest,
        artifactSignature,
        publicKey,
      });
      expect(result.uuid).toBe(uuid);
    });
  });

  describe('#createIntoEntry', () => {
    const envelope = 'some envelope';
    const publicKey = 'a1b2c3';

    const proposedEntry = {
      apiVersion: '0.0.1',
      kind: 'intoto',
      spec: {
        content: { envelope },
        publicKey,
      },
    };

    const uuid =
      '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';
    const responseBody = {
      [uuid]: {},
    };

    beforeEach(() => {
      nock(baseURL)
        .matchHeader('Accept', 'application/json')
        .matchHeader('Content-Type', 'application/json')
        .post('/api/v1/log/entries', proposedEntry)
        .reply(201, responseBody);
    });

    it('submits a new intoto entry', async () => {
      const result = await subject.createIntoEntry({ envelope, publicKey });
      expect(result.uuid).toBe(uuid);
    });
  });

  describe('#getEntry', () => {
    describe('when the entry exists', () => {
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
          'HTTP Error: 404 Not Found'
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
  });

  describe('#searchIndex', () => {
    describe('when matching entries exist', () => {
      const sha =
        'sha256:04c0c13721a28c60f38daf09a05326c301a2cf57ad2beb953eb29d61383db47e';
      const responseBody = ['deadbeef', 'abcd1234'];

      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/index/retrieve', { hash: sha })
          .reply(200, responseBody);
      });

      it('returns matching entries', async () => {
        const response = await subject.searchIndex({ hash: sha });
        expect(response).toEqual(responseBody);
      });
    });

    describe('when no matching entries exist', () => {
      const responseBody = [] as string[];

      beforeEach(() => {
        nock(baseURL).post('/api/v1/index/retrieve').reply(200, responseBody);
      });

      it('returns an empty array', async () => {
        const sha =
          'sha256:04c0c13721a28c60f38daf09a05326c301a2cf57ad2beb953eb29d61383db47e';

        const response = await subject.searchIndex({ hash: sha });

        expect(response).toEqual([]);
      });
    });

    describe('when an error occurs', () => {
      const responseBody = {
        code: 422,
        message: 'Invalid query',
      };

      beforeEach(() => {
        nock(baseURL).get('/api/v1/log/entries/foo').reply(422, responseBody);
      });

      it('returns an error', async () => {
        await expect(subject.getEntry('foo')).rejects.toThrow(
          'HTTP Error: 422 Unprocessable Entity'
        );
      });
    });
  });
});
