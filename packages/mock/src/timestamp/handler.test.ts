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

import { fromPartial } from '@total-typescript/shoehorn';
import { generateKeyPair } from '../util/key';
import { tsaHandler } from './handler';
import { initializeTSA, TSA } from './tsa';

describe('tsaHandler', () => {
  const keyPair = generateKeyPair('prime256v1');

  describe('#path', () => {
    it('returns the correct path', async () => {
      const tsa = await initializeTSA(keyPair);
      const handler = tsaHandler(tsa);
      expect(handler.path).toBe('/api/v1/timestamp');
    });
  });

  describe('#fn', () => {
    it('returns a function', async () => {
      const tsa = await initializeTSA(keyPair);
      const handler = tsaHandler(tsa);
      expect(handler.fn).toBeInstanceOf(Function);
    });

    describe('when invoked', () => {
      const timestampRequest = {
        artifactHash: Buffer.from('foo').toString('base64'),
        hashAlgorithm: 'sha256',
      };

      it('returns a tlog entry', async () => {
        const tsa = await initializeTSA(keyPair);
        const { fn } = tsaHandler(tsa);

        const resp = await fn(JSON.stringify(timestampRequest));
        expect(resp.statusCode).toBe(201);

        // Check the response
        const body = resp.response;
        expect(body).toBeDefined();
      });

      describe('when the TLog raises an error', () => {
        const tsa = fromPartial<TSA>({
          timestamp: async () => {
            throw new Error('oops');
          },
        });

        it('returns 400 error', async () => {
          const { fn } = tsaHandler(tsa, { strict: false });

          // Make a request
          const request = {};

          const resp = await fn(JSON.stringify(request));
          expect(resp.statusCode).toBe(400);
        });
      });
    });
  });
});
