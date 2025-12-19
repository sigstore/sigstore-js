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
import crypto from 'crypto';
import { generateKeyPair } from '../util/key';
import { rekorHandler, rekorV2Handler } from './handler';
import { initializeTLog, TLog } from './tlog';

describe('rekorHandler', () => {
  const url = 'https://rekor.sigstore.dev';
  const keyPair = generateKeyPair();

  describe('#path', () => {
    it('returns the correct path', async () => {
      const tlog = await initializeTLog(url, keyPair);
      const handler = rekorHandler(tlog);
      expect(handler.path).toBe('/api/v1/log/entries');
    });
  });

  describe('#fn', () => {
    it('returns a function', async () => {
      const tlog = await initializeTLog(url, keyPair);
      const handler = rekorHandler(tlog);
      expect(handler.fn).toBeInstanceOf(Function);
    });

    describe('when invoked', () => {
      const proposedEntry = {
        apiVersion: '0.0.1',
        kind: 'hashedrekord',
      };

      it('returns a tlog entry', async () => {
        const tlog = await initializeTLog(url, keyPair);
        const { fn } = rekorHandler(tlog);

        const resp = await fn(JSON.stringify(proposedEntry));
        expect(resp.statusCode).toBe(201);

        // Check the response
        const logID = crypto
          .createHash('sha256')
          .update(tlog.publicKey)
          .digest()
          .toString('hex');

        const body = JSON.parse(resp.response.toString());
        expect(body).toBeDefined();
        expect(Object.keys(body)).toHaveLength(1);

        const uuid = Object.keys(body)[0];
        expect(uuid).toMatch(/^[0-9a-f]{64}$/);

        const entry = body[uuid];
        expect(entry.body).toBeDefined();
        expect(
          JSON.parse(Buffer.from(entry.body, 'base64').toString())
        ).toEqual(proposedEntry);
        expect(entry.integratedTime).toBeGreaterThan(0);
        expect(entry.logID).toBe(logID);
        expect(entry.logIndex).toBeGreaterThan(0);
        expect(entry.verification).toBeDefined();
        expect(entry.verification?.signedEntryTimestamp).toBeDefined();
      });

      describe('when the TLog raises an error', () => {
        const tlog = fromPartial<TLog>({
          log: async () => {
            throw new Error('oops');
          },
        });

        it('returns 400 error', async () => {
          const { fn } = rekorHandler(tlog, { strict: false });

          // Make a request
          const request = {};

          const resp = await fn(JSON.stringify(request));
          expect(resp.statusCode).toBe(400);
        });
      });
    });
  });
});

describe('rekorV2Handler', () => {
  const url = 'https://rekor.sigstore.dev';
  const keyPair = generateKeyPair();

  describe('#path', () => {
    it('returns the correct path', async () => {
      const tlog = await initializeTLog(url, keyPair);
      const handler = rekorV2Handler(tlog);
      expect(handler.path).toBe('/api/v2/log/entries');
    });
  });

  describe('#fn', () => {
    it('returns a function', async () => {
      const tlog = await initializeTLog(url, keyPair);
      const handler = rekorV2Handler(tlog);
      expect(handler.fn).toBeInstanceOf(Function);
    });

    describe('when invoked', () => {
      const ceateEntryRequest = {
        hashedRekordRequestV002: {},
      };

      it('returns a tlog entry', async () => {
        const tlog = await initializeTLog(url, keyPair);
        const { fn } = rekorV2Handler(tlog);

        const resp = await fn(JSON.stringify(ceateEntryRequest));
        expect(resp.statusCode).toBe(201);
        expect(resp.contentType).toBe('application/json');

        // Check the response
        const logID = crypto
          .createHash('sha256')
          .update(tlog.publicKey)
          .digest();

        const body = JSON.parse(resp.response.toString());
        expect(body).toBeDefined();
        expect(body.logId).toBeDefined();
        expect(Buffer.from(body.logId.keyId, 'base64')).toEqual(logID);
        expect(body.kindVersion).toBeDefined();
        expect(body.kindVersion.kind).toBe('hashedrekord');
        expect(body.kindVersion.version).toBe('0.0.2');
        expect(body.logIndex).toBeDefined();
        expect(parseInt(body.logIndex)).toBeGreaterThan(0);
        expect(body.integratedTime).toBeDefined();
        expect(parseInt(body.integratedTime)).toBeGreaterThan(0);
        expect(body.canonicalizedBody).toBeDefined();
        expect(body.inclusionProof).toBeDefined();
        expect(body.inclusionProof.checkpoint).toBeDefined();
      });

      describe('when the TLog raises an error', () => {
        const tlog = fromPartial<TLog>({
          logV2: async () => {
            throw new Error('oops');
          },
        });

        it('returns 400 error', async () => {
          const { fn } = rekorV2Handler(tlog, { strict: false });

          // Make a request
          const request = {};

          const resp = await fn(JSON.stringify(request));
          expect(resp.statusCode).toBe(400);
        });
      });
    });
  });
});
