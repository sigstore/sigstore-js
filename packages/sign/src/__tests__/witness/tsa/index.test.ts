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
import { HashAlgorithm } from '@sigstore/protobuf-specs';
import nock from 'nock';
import { InternalError } from '../../../error';
import { TSAWitness } from '../../../witness/tsa';

import type { SignatureBundle } from '../../../witness';

describe('TSAWitness', () => {
  const tsaBaseURL = 'http://localhost:8080';

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new TSAWitness({ tsaBaseURL });
      expect(client).toBeDefined();
    });
  });

  describe('testify', () => {
    const subject = new TSAWitness({ tsaBaseURL });

    const signature = Buffer.from('signature');

    describe('when TSA returns a timestamp', () => {
      const timestamp = Buffer.from('timestamp');

      beforeEach(() => {
        nock(tsaBaseURL)
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/timestamp')
          .reply(201, timestamp);
      });

      describe('when the signature bundle is a message signature', () => {
        const sigBundle: SignatureBundle = {
          $case: 'messageSignature',
          messageSignature: {
            signature: signature,
            messageDigest: {
              algorithm: HashAlgorithm.SHA2_256,
              digest: Buffer.from('digest'),
            },
          },
        };

        it('returns the timestamp', async () => {
          await expect(subject.testify(sigBundle)).resolves.toEqual({
            rfc3161Timestamps: [{ signedTimestamp: timestamp }],
          });
        });
      });

      describe('when the signature bundle is a DSSE envelope', () => {
        const sigBundle: SignatureBundle = {
          $case: 'dsseEnvelope',
          dsseEnvelope: {
            signatures: [{ keyid: '', sig: signature }],
            payload: Buffer.from('payload'),
            payloadType: 'payloadType',
          },
        };

        it('returns the timestamp', async () => {
          await expect(subject.testify(sigBundle)).resolves.toEqual({
            rfc3161Timestamps: [{ signedTimestamp: timestamp }],
          });
        });
      });
    });

    describe('when TSA returns an error', () => {
      const sigBundle: SignatureBundle = {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          signatures: [{ keyid: '', sig: signature }],
          payload: Buffer.from('payload'),
          payloadType: 'payloadType',
        },
      };

      beforeEach(() => {
        nock(tsaBaseURL)
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/timestamp')
          .reply(500, {});
      });

      it('returns an error', async () => {
        await expect(subject.testify(sigBundle)).rejects.toThrowWithCode(
          InternalError,
          'TSA_CREATE_TIMESTAMP_ERROR'
        );
      });
    });
  });
});
