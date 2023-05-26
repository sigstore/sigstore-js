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
import { InternalError } from '../../../error';
import * as sigstore from '../../../types/sigstore';
import { RekorWitness } from '../../../witness/tlog';

import assert from 'assert';
import type { SignatureBundle } from '../../../witness';

describe('RekorWitness', () => {
  const rekorBaseURL = 'http://localhost:8080';

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new RekorWitness({ rekorBaseURL });
      expect(client).toBeDefined();
    });
  });

  describe('testify', () => {
    const subject = new RekorWitness({ rekorBaseURL });
    const signature = Buffer.from('signature');
    const publicKey = 'publickey';

    describe('when Rekor returns a valid response', () => {
      const uuid =
        '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

      const proposedEntry = {
        apiVersion: '0.0.1',
        kind: 'foo',
      };

      const rekorEntry = {
        [uuid]: {
          body: Buffer.from(JSON.stringify(proposedEntry)).toString('base64'),
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
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries')
          .reply(201, rekorEntry);
      });

      describe('when the signature bundle is a message signature', () => {
        const sigBundle: SignatureBundle = {
          $case: 'messageSignature',
          messageSignature: {
            signature: signature,
            messageDigest: {
              algorithm: sigstore.HashAlgorithm.SHA2_256,
              digest: Buffer.from('digest'),
            },
          },
        };

        it('returns the tlog entry', async () => {
          const affidavit = await subject.testify(sigBundle, publicKey);

          expect(affidavit).toBeDefined();
          expect(affidavit.rfc3161Timestamps).toBeUndefined();

          assert(affidavit.tlogEntries);
          expect(affidavit.tlogEntries).toHaveLength(1);

          const tlogEntry = affidavit.tlogEntries[0];
          expect(tlogEntry).toBeDefined();
          expect(tlogEntry.logIndex).toEqual(
            rekorEntry[uuid].logIndex.toString()
          );
          expect(tlogEntry.logId?.keyId).toEqual(
            Buffer.from(rekorEntry[uuid].logID, 'hex')
          );
          expect(tlogEntry.kindVersion?.kind).toEqual(proposedEntry.kind);
          expect(tlogEntry.kindVersion?.version).toEqual(
            proposedEntry.apiVersion
          );
          expect(tlogEntry.integratedTime).toEqual(
            rekorEntry[uuid].integratedTime.toString()
          );
          expect(tlogEntry.inclusionPromise?.signedEntryTimestamp).toEqual(
            Buffer.from(
              rekorEntry[uuid].verification.signedEntryTimestamp,
              'base64'
            )
          );
          expect(tlogEntry.inclusionProof).toBeUndefined();
          expect(tlogEntry.canonicalizedBody).toEqual(
            Buffer.from(rekorEntry[uuid].body, 'base64')
          );
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

        it('returns the tlog entry', async () => {
          const affidavit = await subject.testify(sigBundle, publicKey);

          expect(affidavit).toBeDefined();
          expect(affidavit.rfc3161Timestamps).toBeUndefined();

          assert(affidavit.tlogEntries);
          expect(affidavit.tlogEntries).toHaveLength(1);

          const tlogEntry = affidavit.tlogEntries[0];
          expect(tlogEntry).toBeDefined();
          expect(tlogEntry.logIndex).toEqual(
            rekorEntry[uuid].logIndex.toString()
          );
          expect(tlogEntry.logId?.keyId).toEqual(
            Buffer.from(rekorEntry[uuid].logID, 'hex')
          );
          expect(tlogEntry.kindVersion?.kind).toEqual(proposedEntry.kind);
          expect(tlogEntry.kindVersion?.version).toEqual(
            proposedEntry.apiVersion
          );
          expect(tlogEntry.integratedTime).toEqual(
            rekorEntry[uuid].integratedTime.toString()
          );
          expect(tlogEntry.inclusionPromise?.signedEntryTimestamp).toEqual(
            Buffer.from(
              rekorEntry[uuid].verification.signedEntryTimestamp,
              'base64'
            )
          );
          expect(tlogEntry.inclusionProof).toBeUndefined();
          expect(tlogEntry.canonicalizedBody).toEqual(
            Buffer.from(rekorEntry[uuid].body, 'base64')
          );
        });
      });
    });

    describe('when Rekor returns an entry w/o verification data', () => {
      const sigBundle: SignatureBundle = {
        $case: 'messageSignature',
        messageSignature: {
          signature: signature,
          messageDigest: {
            algorithm: sigstore.HashAlgorithm.SHA2_256,
            digest: Buffer.from('digest'),
          },
        },
      };

      const uuid =
        '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

      const proposedEntry = {
        apiVersion: '0.0.1',
        kind: 'foo',
      };

      const rekorEntry = {
        [uuid]: {
          body: Buffer.from(JSON.stringify(proposedEntry)).toString('base64'),
          integratedTime: 1654015743,
          logID:
            'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
          logIndex: 2513258,
        },
      };

      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries')
          .reply(201, rekorEntry);
      });

      it('returns the tlog entry with an empty SET', async () => {
        const affidavit = await subject.testify(sigBundle, publicKey);

        expect(affidavit).toBeDefined();
        assert(affidavit.tlogEntries);

        expect(affidavit.tlogEntries).toHaveLength(1);
        const tlogEntry = affidavit.tlogEntries[0];
        expect(tlogEntry.inclusionPromise?.signedEntryTimestamp).toEqual(
          Buffer.from('')
        );
      });
    });

    describe('when Rekor returns an error', () => {
      const sigBundle: SignatureBundle = {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          signatures: [{ keyid: '', sig: signature }],
          payload: Buffer.from('payload'),
          payloadType: 'payloadType',
        },
      };

      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries')
          .reply(500, {});
      });

      it('returns an error', async () => {
        await expect(
          subject.testify(sigBundle, publicKey)
        ).rejects.toThrowWithCode(InternalError, 'TLOG_CREATE_ENTRY_ERROR');
      });
    });
  });
});
