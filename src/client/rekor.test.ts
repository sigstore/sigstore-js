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

  describe('#searchLog', () => {
    const searchLogURL = '/api/v1/log/entries/retrieve';

    const searchLogEntryUUID =
      '5c1419ace1915869eef4426701d0763232da44d453e31ffc06d60ea61de36e25';
    const searchLogIndex = 3244486;

    const searchLogEntry = {
      kind: 'hashedrekord',
      apiVersion: '0.0.1',
      spec: {
        data: {
          hash: {
            value:
              'c0afcf83aee6ee83b2ecfa226db62853fd77bcaf550e1b4bf277acbe38a67bca',
            algorithm: 'sha256',
          },
        },
        signature: {
          content:
            'MEYCIQDXxhsvLwEXG9HFrYyF/FgGbo0Ja25ADoaUhs+4DqaCQgIhAJziarK6mxXB5coQu75jpHSbXAGQyDE8tu8sTrcXndGV',
          publicKey: {
            content:
              'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvRENDQWlhZ0F3SUJBZ0lVZTR4VXljdWRlbW9sVG5tenpCVnM0MVNNQU9Jd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09ESXlNVGd3T1RBeVdoY05Nakl3T0RJeU1UZ3hPVEF5V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDV3dEM1F6WUwwN2JDY0JrZURWU3hUOE9FQnM1MnJXcS9aZGYKMEZFSlZneng3cGpyZFFmOExBOEp6dkZkVnhKeXBGSDVVcythMkRRRWVUdytlZUNRcEtPQ0FVVXdnZ0ZCTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVodUt1CklsWFVHa3VrM2prbWJ3SlhpeDh1cFdrd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0h3WURWUjBSQVFIL0JCVXdFNEVSWW5KcFlXNUFaR1ZvWVcxbGNpNWpiMjB3TEFZS0t3WUJCQUdEdnpBQgpBUVFlYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJ4dloybHVMMjloZFhSb01JR0tCZ29yQmdFRUFkWjVBZ1FDCkJId0VlZ0I0QUhZQUNHQ1M4Q2hTLzJoRjBkRnJKNFNjUldjWXJCWTl3empTYmVhOElnWTJiM0lBQUFHQ3hyNWkKZ3dBQUJBTUFSekJGQWlCOEFPQ2t2VnA1bGRhVkVuMk96NlAzUE5YOGd2cGt2WmlqUEZ2SHY1ZHMvZ0loQUtWNAplK1lpKzVpa2VCYTU3UlV1alMrV3RIdklSeEJBVVRNK2hTOE5XWHFjTUFvR0NDcUdTTTQ5QkFNREEyZ0FNR1VDCk1RQ3JIK3krYkhDeCtBR0lsc3JOeXhOa2VsS3hSNDAwbEpzd1FBVDVOVk5aUmVSUDBhbDJKN1dmSHhyZVhqS0oKT2ZBQ01FTnpzUjhIeVZpOEJuZDBPd1YzOGswMGRnZW9PTGoycTgwZVdEbWJWN1ptVklyeDRpc2M4aFVnNHFHLwpKN2x4TEE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==',
          },
        },
      },
    };

    const searchLogResponseBody = [
      {
        [searchLogEntryUUID]: {
          body: 'eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJjMGFmY2Y4M2FlZTZlZTgzYjJlY2ZhMjI2ZGI2Mjg1M2ZkNzdiY2FmNTUwZTFiNGJmMjc3YWNiZTM4YTY3YmNhIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUURYeGhzdkx3RVhHOUhGcll5Ri9GZ0dibzBKYTI1QURvYVVocys0RHFhQ1FnSWhBSnppYXJLNm14WEI1Y29RdTc1anBIU2JYQUdReURFOHR1OHNUcmNYbmRHViIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTnZSRU5EUVdsaFowRjNTVUpCWjBsVlpUUjRWWGxqZFdSbGJXOXNWRzV0ZW5wQ1ZuTTBNVk5OUVU5SmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEpkMDlFU1hsTlZHZDNUMVJCZVZkb1kwNU5ha2wzVDBSSmVVMVVaM2hQVkVGNVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZEVjNkRU0xRjZXVXd3TjJKRFkwSnJaVVJXVTNoVU9FOUZRbk0xTW5KWGNTOWFaR1lLTUVaRlNsWm5lbmczY0dweVpGRm1PRXhCT0VwNmRrWmtWbmhLZVhCR1NEVlZjeXRoTWtSUlJXVlVkeXRsWlVOUmNFdFBRMEZWVlhkblowWkNUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZvZFV0MUNrbHNXRlZIYTNWck0ycHJiV0ozU2xocGVEaDFjRmRyZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBoM1dVUldVakJTUVZGSUwwSkNWWGRGTkVWU1dXNUtjRmxYTlVGYVIxWnZXVmN4YkdOcE5XcGlNakIzVEVGWlMwdDNXVUpDUVVkRWRucEJRZ3BCVVZGbFlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVlpNamwwVERKNGRsb3liSFZNTWpsb1pGaFNiMDFKUjB0Q1oyOXlRbWRGUlVGa1dqVkJaMUZEQ2tKSWQwVmxaMEkwUVVoWlFVTkhRMU00UTJoVEx6Sm9SakJrUm5KS05GTmpVbGRqV1hKQ1dUbDNlbXBUWW1WaE9FbG5XVEppTTBsQlFVRkhRM2h5TldrS1ozZEJRVUpCVFVGU2VrSkdRV2xDT0VGUFEydDJWbkExYkdSaFZrVnVNazk2TmxBelVFNVlPR2QyY0d0MldtbHFVRVoyU0hZMVpITXZaMGxvUVV0V05BcGxLMWxwS3pWcGEyVkNZVFUzVWxWMWFsTXJWM1JJZGtsU2VFSkJWVlJOSzJoVE9FNVhXSEZqVFVGdlIwTkRjVWRUVFRRNVFrRk5SRUV5WjBGTlIxVkRDazFSUTNKSUsza3JZa2hEZUN0QlIwbHNjM0pPZVhoT2EyVnNTM2hTTkRBd2JFcHpkMUZCVkRWT1ZrNWFVbVZTVURCaGJESktOMWRtU0hoeVpWaHFTMG9LVDJaQlEwMUZUbnB6VWpoSWVWWnBPRUp1WkRCUGQxWXpPR3N3TUdSblpXOVBUR295Y1Rnd1pWZEViV0pXTjFwdFZrbHllRFJwYzJNNGFGVm5OSEZITHdwS04yeDRURUU5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19',
          integratedTime: 1661191742,
          logID:
            'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
          logIndex: searchLogIndex,
          verification: {
            inclusionProof: {
              hashes: [
                'a95557f9140686a8232d87372d63f77d238b9b592546793122fee610a98bdc4a',
                '755c2d4215b65ff1e89922eaf3d0b0c2a256bb73f01c9987d0baf7da6bd05ce9',
                'a40ef3cc1d74b6c51d7f10bd27c3fdaf32a0ef5ff3b7d1a920e2cab3fd7b15fa',
                'f13869de51fd02503c70fc7b60a0a45f63e5ac7f5e09e1f8481fb3c27dde3787',
                '8f940f0ea5c5a2f851c0bb5a736a1be56a2fb823c5e805521ba7e354d0046e4a',
                '7158f9f9011dae7f3ac2bd2ca20b3dc8994498ba16cf58d5be94586db4b7049b',
                '7905df410a38ed98d7d3f84a2ec4aea550e1b958ccd767c0daefcee7a2b9037a',
                '497906c322703a983d84cb7618b74ba0804b245c63ef0a276cf1db8b9cee487a',
                'a547f0e05745e0594c9569c04e5d7eff0aed47f88eaf50e373b051ed465bd61d',
                '0d7e8078654eb19540634cb8e1c5a864424e4b03e65f7fb139746a279fd0b3cc',
                'a64451821ac29b58a6ced95c615e426fc339d3607b0001c4298c474b7fdaed59',
                'b71e915675080279e58cdd0daa859a47da7e824ffc55df612becfcfb2fd9aae8',
                '6d494b237648126525b08f975c736a55d1f7a64472fcc2782bbc16733c608d7b',
                'efb36cfc54705d8cd921a621a9389ffa03956b15d68bfabadac2b4853852079b',
              ],
              logIndex: searchLogIndex,
              rootHash:
                'ba3be49521f0cf6eed57b0e1ffe4b47a2f5b96bf43e9b6eb5ec3130f80e53c8d',
              treeSize: 3244712,
            },
            signedEntryTimestamp:
              'MEUCIQDLNuDkFSpqhFBpp3o1ApYu4WH0f4tP2OWZC/o+f79cQAIgFC6uELUYcUpPNACyu89pNynxmmrWMdzu08CNNYl83/c=',
          },
        },
      },
    ];

    describe('when matching by entry', () => {
      const entries = [searchLogEntry];
      const responseBody = searchLogResponseBody;

      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post(searchLogURL, { entries })
          .reply(200, responseBody);
      });

      it('returns matching entries', async () => {
        const response = await subject.searchLog({
          entries: entries as HashedRekordKind[],
        });

        expect(response).toHaveLength(1);
        expect(response[0].uuid).toEqual(
          Object.keys(searchLogResponseBody[0])[0]
        );
        expect(response[0].logIndex).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].logIndex
        );
        expect(response[0].body).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].body
        );
        expect(response[0].integratedTime).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].integratedTime
        );
        expect(response[0].logID).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].logID
        );
        expect(response[0].verification).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].verification
        );
      });
    });

    describe('when matching by log index', () => {
      const logIndexes = [searchLogIndex];
      const responseBody = searchLogResponseBody;

      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post(searchLogURL, { logIndexes })
          .reply(200, responseBody);
      });

      it('returns matching entries', async () => {
        const response = await subject.searchLog({ logIndexes });
        expect(response).toHaveLength(1);
        expect(response[0].uuid).toEqual(
          Object.keys(searchLogResponseBody[0])[0]
        );
        expect(response[0].logIndex).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].logIndex
        );
        expect(response[0].body).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].body
        );
        expect(response[0].integratedTime).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].integratedTime
        );
        expect(response[0].logID).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].logID
        );
        expect(response[0].verification).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].verification
        );
      });
    });

    describe('when matching by UUID', () => {
      const entryUUIDs = [searchLogEntryUUID];

      const responseBody = searchLogResponseBody;

      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post(searchLogURL, { entryUUIDs })
          .reply(200, responseBody);
      });

      it('returns matching entries', async () => {
        const response = await subject.searchLog({ entryUUIDs });
        expect(response).toHaveLength(1);
        expect(response[0].uuid).toEqual(
          Object.keys(searchLogResponseBody[0])[0]
        );
        expect(response[0].logIndex).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].logIndex
        );
        expect(response[0].body).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].body
        );
        expect(response[0].integratedTime).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].integratedTime
        );
        expect(response[0].logID).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].logID
        );
        expect(response[0].verification).toEqual(
          searchLogResponseBody[0][searchLogEntryUUID].verification
        );
      });
    });

    describe('when no matching entries exist', () => {
      const responseBody = [] as string[];

      beforeEach(() => {
        nock(baseURL).post(searchLogURL).reply(200, responseBody);
      });

      it('returns an empty array', async () => {
        const entryUUIDs = [searchLogEntryUUID];

        const response = await subject.searchLog({ entryUUIDs });

        expect(response).toEqual([]);
      });
    });
  });
});
