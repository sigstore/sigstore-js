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
import { mockTSA } from '@sigstore/mock';
import nock from 'nock';
import { InternalError } from '../../../error';
import { crypto } from '../../../util';
import { TSAClient } from '../../../witness/tsa/client';

describe('TSAClient', () => {
  const baseURL = 'http://localhost:8080';

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new TSAClient({ tsaBaseURL: baseURL });
      expect(client).toBeDefined();
    });
  });

  describe('createTimestamp', () => {
    const subject = new TSAClient({ tsaBaseURL: baseURL });

    const signature = Buffer.from('signature');

    const request = {
      artifactHash: crypto.hash(signature).toString('base64'),
      hashAlgorithm: 'sha256',
    };

    describe('when TSA returns a timestamp', () => {
      beforeEach(async () => {
        await mockTSA({ baseURL });
      });

      it('returns the timestamp', async () => {
        const timestamp = await subject.createTimestamp(signature);

        expect(timestamp).toBeDefined();
        expect(timestamp.byteLength).toBeGreaterThan(0);
      });
    });

    describe('when TSA returns an error', () => {
      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/timestamp', request)
          .reply(500, {});
      });

      it('returns an error', async () => {
        await expect(
          subject.createTimestamp(signature)
        ).rejects.toThrowWithCode(InternalError, 'TSA_CREATE_TIMESTAMP_ERROR');
      });
    });

    describe('when TSA successfully returns a timestamp after retry', () => {
      let scope: nock.Scope;
      beforeEach(async () => {
        scope = nock(baseURL)
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/timestamp', request)
          .reply(500, {});
        await mockTSA({ baseURL });
      });

      it('returns the timestamp', async () => {
        const subject = new TSAClient({
          tsaBaseURL: baseURL,
          retry: { retries: 1, factor: 0, minTimeout: 1, maxTimeout: 1 },
        });
        const timestamp = await subject.createTimestamp(signature);

        expect(timestamp).toBeDefined();
        expect(timestamp.byteLength).toBeGreaterThan(0);
        expect(scope.isDone()).toBe(true);
      });
    });
  });
});
