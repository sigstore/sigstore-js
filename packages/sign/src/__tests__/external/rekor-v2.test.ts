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
import { RekorV2 } from '../../external/rekor-v2';

import { PublicKeyDetails } from '@sigstore/protobuf-specs';
import { CreateEntryRequest } from '@sigstore/protobuf-specs/rekor/v2';

describe('RekorV2', () => {
  const baseURL = 'http://localhost:8080';
  const subject = new RekorV2({ baseURL });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#createEntry', () => {
    // Create a minimal valid HashedRekordRequestV002 entry for v2 API
    const proposedEntry: CreateEntryRequest = {
      spec: {
        $case: 'hashedRekordRequestV002',
        hashedRekordRequestV002: {
          digest: Buffer.from(
            '5dJ2SakUeOXY4ut1hBHPomz+hTn6tc0KTzcGosA+epE=',
            'base64'
          ), //
          signature: {
            content: Buffer.from(
              'MEUCIG4QZL8qNVlYtlzSP8GoUUBWZm+VX4nMpxuSeryLFLq8AiEAzGwoNj4Z0PMvbXjC/4aQT5IaBtMSvANyuV4LoF6uLI0=',
              'base64'
            ),
            verifier: {
              verifier: {
                $case: 'publicKey',
                publicKey: {
                  rawBytes: Buffer.from(
                    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0q9Q+tdG195CXKfmUx1YatvZ/mN3rhjpOfm1lvskWprH9Pxpe9Xc6LjEJbBcVPhutkfUvBB9RDk+42SNE6/5xg==',
                    'base64'
                  ),
                },
              },
              keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
            },
          },
        },
      },
    };

    const responseBody = {
      logIndex: '412114',
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
        logIndex: '412114',
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
      canonicalizedBody:
        'eyJhcGlWZXJzaW9uIjoiMC4wLjIiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJoYXNoZWRSZWtvcmRWMDAyIjp7ImRhdGEiOnsiYWxnb3JpdGhtIjoiU0hBMl8yNTYiLCJkaWdlc3QiOiI1ZEoyU2FrVWVPWFk0dXQxaEJIUG9teitoVG42dGMwS1R6Y0dvc0ErZXBFPSJ9LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUURjSk84Mm56MXJydHUxRHhTcHJ1WDFvZ0p1bThkbDRJaUdCTVB6M2pZY2JnSWhBS3dROHdOdTFPbjhwWWZoQUpDSzhPcVQwT09HVGgveUFRK0FuL2UzZC9kVSIsInZlcmlmaWVyIjp7ImtleURldGFpbHMiOiJQS0lYX0VDRFNBX1AyNTZfU0hBXzI1NiIsInB1YmxpY0tleSI6eyJyYXdCeXRlcyI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRTBxOVErdGRHMTk1Q1hLZm1VeDFZYXR2Wi9tTjNyaGpwT2ZtMWx2c2tXcHJIOVB4cGU5WGM2TGpFSmJCY1ZQaHV0a2ZVdkJCOVJEays0MlNORTYvNXhnPT0ifX19fX19',
    };

    describe('when the entry is successfully added', () => {
      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('User-Agent', new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'))
          .post('/api/v2/log/entries')
          .reply(201, responseBody);
      });

      it('returns the new entry', async () => {
        const result = await subject.createEntry(proposedEntry);

        expect(result).toBeDefined();
        expect(result.logIndex).toBeDefined();
        expect(typeof result.logIndex).toBe('string');
        expect(result.logId).toBeDefined();
        expect(result.logId?.keyId).toBeDefined();
        expect(result.integratedTime).toBeDefined();
        expect(typeof result.integratedTime).toBe('string');
        expect(result.kindVersion).toBeDefined();
        expect(result.kindVersion?.kind).toBe('hashedrekord');
        expect(result.inclusionPromise).toBeDefined();
      });
    });

    describe('when a matching entry already exists', () => {
      const responseBody = {
        code: 409,
        message: 'An equivalent entry already exists',
      };

      beforeEach(() => {
        nock(baseURL).post('/api/v2/log/entries').reply(409, responseBody);
      });

      it('returns an error', async () => {
        await expect(subject.createEntry(proposedEntry)).rejects.toThrow(
          '(409) An equivalent entry already exists'
        );
      });
    });
  });
});
