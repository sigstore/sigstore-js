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

import crypto from 'crypto';
import { generateKeyPair } from '../util/key';
import { initializeTLog } from './tlog';

import { PublicKeyDetails } from '@sigstore/protobuf-specs';
import type { CreateEntryRequest } from '@sigstore/protobuf-specs/rekor/v2';

describe('TLog', () => {
  const url = 'https://tlog.sigstore.dev';
  const keyPair = generateKeyPair();

  describe('#publicKey', () => {
    it('should be a public key', async () => {
      const subject = await initializeTLog(url, keyPair);
      expect(subject.publicKey).toBeDefined();
    });
  });

  describe('#log', () => {
    it('returns an entry', async () => {
      const proposedEntry = { foo: 'bar' };
      const subject = await initializeTLog(url, keyPair);
      const result = await subject.log(proposedEntry);

      const logID = crypto
        .createHash('sha256')
        .update(subject.publicKey)
        .digest()
        .toString('hex');

      expect(Object.keys(result)).toHaveLength(1);
      const uuid = Object.keys(result)[0];
      expect(uuid).toMatch(/^[0-9a-f]{64}$/);

      const entry = result[uuid];
      expect(entry.body).toBeDefined();
      expect(typeof entry.body).toBe('string');
      expect(JSON.parse(Buffer.from(entry.body, 'base64').toString())).toEqual(
        proposedEntry
      );
      expect(entry.integratedTime).toBeGreaterThan(0);
      expect(entry.logID).toEqual(logID);
      expect(entry.logIndex).toBeGreaterThan(0);
      expect(entry.verification).toBeDefined();
      expect(entry.verification?.signedEntryTimestamp).toBeDefined();
      expect(entry.verification?.inclusionProof).toBeDefined();
      expect(entry.verification?.inclusionProof?.logIndex).toBe(0);
      expect(entry.verification?.inclusionProof?.treeSize).toBe(1);
      expect(entry.verification?.inclusionProof?.rootHash).toBeDefined();
      expect(entry.verification?.inclusionProof?.hashes).toHaveLength(0);
      expect(entry.verification?.inclusionProof?.checkpoint).toBeDefined();
    });

    it('canonicalizes the entry and signs its metadata', async () => {
      const subject = await initializeTLog(url, keyPair);
      const result = await subject.log({
        z: [{ b: 2, a: 1 }],
        a: 'example',
      });
      const entry = Object.values(result)[0];
      const body = Buffer.from(entry.body, 'base64').toString('utf8');

      expect(body).toBe('{"a":"example","z":[{"a":1,"b":2}]}');

      const set = JSON.stringify({
        body: entry.body,
        integratedTime: entry.integratedTime,
        logID: entry.logID,
        logIndex: entry.logIndex,
      });
      const signature = Buffer.from(
        entry.verification!.signedEntryTimestamp!,
        'base64'
      );
      expect(
        crypto.verify('sha256', Buffer.from(set), keyPair.publicKey, signature)
      ).toBe(true);
    });

    it('handles values without a JSON representation', async () => {
      const subject = await initializeTLog(url, keyPair);
      const result = await subject.log({
        omit: () => 'unused',
        toJSON: { toJSON: () => undefined },
        array: [undefined, () => 'unused'],
      });
      const entry = Object.values(result)[0];

      expect(Buffer.from(entry.body, 'base64').toString('utf8')).toBe(
        '{"array":[null,null]}'
      );
    });

    it('rejects strings containing unpaired surrogates', async () => {
      const subject = await initializeTLog(url, keyPair);

      await expect(subject.log({ text: '\ud800' })).rejects.toThrow(
        'Lone surrogate is not allowed'
      );
    });
  });

  describe('#logV2', () => {
    it('returns a TransparencyLogEntry for hashedrekord', async () => {
      const proposedEntry: CreateEntryRequest = {
        spec: {
          $case: 'hashedRekordRequestV002',
          hashedRekordRequestV002: {
            digest: Buffer.from('test-digest'),
            signature: {
              content: Buffer.from('test-signature'),
              verifier: {
                keyDetails: PublicKeyDetails.PUBLIC_KEY_DETAILS_UNSPECIFIED,
                verifier: {
                  $case: 'publicKey',
                  publicKey: {
                    rawBytes: Buffer.from('test-key'),
                  },
                },
              },
            },
          },
        },
      };
      const subject = await initializeTLog(url, keyPair);
      const result = await subject.logV2(proposedEntry);

      const logID = crypto
        .createHash('sha256')
        .update(subject.publicKey)
        .digest();

      expect(result.logId).toBeDefined();
      expect(result.logId?.keyId).toEqual(logID);
      expect(result.kindVersion).toBeDefined();
      expect(result.kindVersion?.kind).toBe('hashedrekord');
      expect(result.kindVersion?.version).toBe('0.0.2');
      expect(result.logIndex).toBeDefined();
      expect(parseInt(result.logIndex)).toBeGreaterThan(0);
      expect(result.integratedTime).toBeDefined();
      expect(parseInt(result.integratedTime)).toBeGreaterThan(0);
      expect(result.canonicalizedBody).toBeDefined();
      expect(result.inclusionPromise).toBeUndefined();
      expect(result.inclusionProof).toBeDefined();
      expect(result.inclusionProof?.logIndex).toBeDefined();
      expect(result.inclusionProof?.treeSize).toBe('1');
      expect(result.inclusionProof?.rootHash).toBeDefined();
      expect(result.inclusionProof?.hashes).toHaveLength(0);
      expect(result.inclusionProof?.checkpoint).toBeDefined();
      expect(result.inclusionProof?.checkpoint?.envelope).toBeDefined();
    });

    it('returns a TransparencyLogEntry for dsse', async () => {
      const proposedEntry: CreateEntryRequest = {
        spec: {
          $case: 'dsseRequestV002',
          dsseRequestV002: {
            envelope: {
              payloadType: 'test-payload-type',
              payload: Buffer.from('test-payload'),
              signatures: [
                {
                  keyid: 'test-keyid',
                  sig: Buffer.from('test-signature'),
                },
              ],
            },
            verifiers: [
              {
                keyDetails: PublicKeyDetails.PUBLIC_KEY_DETAILS_UNSPECIFIED,
                verifier: {
                  $case: 'publicKey',
                  publicKey: {
                    rawBytes: Buffer.from('test-key'),
                  },
                },
              },
            ],
          },
        },
      };
      const subject = await initializeTLog(url, keyPair);
      const result = await subject.logV2(proposedEntry);

      expect(result.kindVersion?.kind).toBe('dsse');
      expect(result.kindVersion?.version).toBe('0.0.2');
    });
  });
});
