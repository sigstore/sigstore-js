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

import { Verifier } from './verify';
import { hash } from './crypto';
import { base64Decode, base64Encode } from './util';
import { Rekor } from './client';

describe('Verifier', () => {
  const rekorBaseURL = 'http://localhost:8002';
  const rekor = new Rekor({ baseURL: rekorBaseURL });
  const subject = new Verifier({ rekor });

  describe('#verify', () => {
    const payload = Buffer.from('Hello, world!');
    const signature =
      'MEUCIFRsQUBCo06j+lKpCx2XaaVS0N+f6czW8aBsgek5aeoZAiEA/A2KUxPCvxFjFu184a1256IGVmiFfZagq5Pm0yUgQLU=';

    // Cert that could have generated the signature above
    const signingCert =
      'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN1RENDQWoyZ0F3SUJBZ0lVVmV0U01RemZUbXVrTTlDSnV0KytId3AvWThzd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd05qQTRNVGN3TXpFeVdoY05Nakl3TmpBNE1UY3hNekV5V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV0T2N5a0lMREVTVDNwN2JkZ24zMjYyS1pWSXlHL0F2SDl6ZG0KUVdDMXlpR2tVV2ZqVVF5aCtWSTVselEyQXFxdVR3QlFYZDdCcDRlaFFwYzRYaVpqQTZPQ0FWd3dnZ0ZZTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVKWi8xCmRpTEhENDNvdUhneWhrcnF6QnRFTGt3d0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d09RWURWUjBSQVFIL0JDOHdMWUVyWVhKMGMybG5ibVZ5UUdSbGFHRnRaWEl5TkM1cFlXMHVaM05sY25acApZMlZoWTJOdmRXNTBMbU52YlRBcEJnb3JCZ0VFQVlPL01BRUJCQnRvZEhSd2N6b3ZMMkZqWTI5MWJuUnpMbWR2CmIyZHNaUzVqYjIwd2dZb0dDaXNHQVFRQjFua0NCQUlFZkFSNkFIZ0FkZ0FJWUpMd0tGTC9hRVhSMFdzbmhKeEYKWnhpc0ZqM0RPTkp0NXJ3aUJqWnZjZ0FBQVlGRVJTak1BQUFFQXdCSE1FVUNJUURRYUNLYlhtTnBqWDExSVVhZwpoNk5DbWtsaURwR3pBTXdEY0xaWHYzVUdyd0lnY29zNGZqR1RiOGFEb2NhNk9FOEowNEJWYko1VzB1OHNyU1FjCjF6bDdhd0F3Q2dZSUtvWkl6ajBFQXdNRGFRQXdaZ0l4QUpERlc4bGJDVUhPL1Qzb0Z2TVc3WXhYQlBWdXM2UjkKN0xhY0N4aE9zbHpYWUFhMXdtWks0VXlnTHZFS3pITER1Z0l4QVBpRlI2RWtBRWtCYkJzQ2Q4aU1xZ3R0Rmp1QQpaQURrWjFiTGdaU1VPSEVyVjUvMGluZDFaSGtNcnE1ZHJDeFpvUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K';

    describe('when a certificate is supplied', () => {
      describe('when the signature and the cert match', () => {
        it('returns true', async () => {
          const verified = await subject.verify(
            payload,
            signature,
            base64Decode(signingCert)
          );

          expect(verified).toBe(true);
        });
      });

      describe('when the signature and the cert do NOT match', () => {
        it('returns false', async () => {
          const verified = await subject.verify(
            payload,
            '',
            base64Decode(signingCert)
          );

          expect(verified).toBe(false);
        });
      });
    });

    describe('when a certificate is NOT supplied', () => {
      describe('when a matching entry is found in Rekor', () => {
        // Rekor output
        const uuid = 'a0b1c2d3e4f5';

        const signatureBundle = {
          spec: {
            signature: {
              content: signature,
              publicKey: { content: signingCert },
            },
          },
        };

        const rekorEntry = {
          [uuid]: {
            body: base64Encode(JSON.stringify(signatureBundle)),
          },
        };

        beforeEach(() => {
          // Mock the lookup of the artifact digest in Rekor
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .matchHeader('Content-Type', 'application/json')
            .post('/api/v1/index/retrieve', { hash: `sha256:${hash(payload)}` })
            .reply(200, [uuid]);

          // Mock the lookup of the Rekor entry
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .get(`/api/v1/log/entries/${uuid}`)
            .reply(200, rekorEntry);
        });

        it('returns true', async () => {
          const flag = await subject.verify(payload, signature);
          expect(flag).toBe(true);
        });
      });

      describe('when artifact digest is NOT found in Rekor', () => {
        beforeEach(() => {
          // Mock the lookup of the artifact digest in Rekor
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .matchHeader('Content-Type', 'application/json')
            .post('/api/v1/index/retrieve', { hash: `sha256:${hash(payload)}` })
            .reply(200, []);
        });

        it('returns false', async () => {
          const flag = await subject.verify(payload, signature);
          expect(flag).toBe(false);
        });
      });

      describe('when artifact signature is NOT found in Rekor', () => {
        // Rekor output
        const uuid = 'a0b1c2d3e4f5';

        const signatureBundle = {
          spec: {
            signature: {
              content: 'ABC123',
              publicKey: { content: signingCert },
            },
          },
        };

        const rekorEntry = {
          [uuid]: {
            body: base64Encode(JSON.stringify(signatureBundle)),
          },
        };

        beforeEach(() => {
          // Mock the lookup of the artifact digest in Rekor
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .matchHeader('Content-Type', 'application/json')
            .post('/api/v1/index/retrieve', { hash: `sha256:${hash(payload)}` })
            .reply(200, [uuid]);

          // Mock the lookup of the Rekor entry
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .get(`/api/v1/log/entries/${uuid}`)
            .reply(200, rekorEntry);
        });

        it('returns false', async () => {
          const flag = await subject.verify(payload, signature);
          expect(flag).toBe(false);
        });
      });
    });
  });
});
