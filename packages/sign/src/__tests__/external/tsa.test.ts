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
import { TimestampAuthority, TimestampRequest } from '../../external/tsa';

describe('TimestampAuthority', () => {
  const baseURL = 'http://localhost:8000';
  const subject = new TimestampAuthority({ baseURL });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#createTimestamp', () => {
    const timestampRequest = {
      artifactHash: 'artifacthash',
      hashAlgorithm: 'sha256',
    } satisfies TimestampRequest;

    describe('when the timestamp request is valid', () => {
      const timestamp = Buffer.from('timestamp');

      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('User-Agent', new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'))
          .post('/api/v1/timestamp', timestampRequest)
          .reply(200, timestamp);
      });

      it('returns the timestamp', async () => {
        const result = await subject.createTimestamp(timestampRequest);
        expect(result).toEqual(timestamp);
      });
    });

    describe('when the timestamp request is invalid', () => {
      const responseBody = {
        code: 400,
        message: 'Error generating timestamp response',
      };

      beforeEach(() => {
        nock(baseURL).post('/api/v1/timestamp').reply(400, responseBody);
      });

      it('returns an error', async () => {
        await expect(subject.createTimestamp(timestampRequest)).rejects.toThrow(
          '(400) Error generating timestamp response'
        );
      });
    });
  });
});
