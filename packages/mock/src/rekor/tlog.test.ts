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
  });
});
