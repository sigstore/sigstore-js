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
import { CTLog, initializeCTLog } from './ctlog';

describe('CTLog', () => {
  const keyPair = generateKeyPair();
  describe('initializeCTLog', () => {
    it('returns a CTLog', async () => {
      const ctLog: CTLog = await initializeCTLog(keyPair);
      expect(ctLog).toBeDefined();
    });
  });

  describe('#publicKey', () => {
    it('returns a key', async () => {
      const ctLog: CTLog = await initializeCTLog(keyPair);
      expect(ctLog.publicKey).toBeDefined();
    });
  });

  describe('#logID', () => {
    it('returns the log ID', async () => {
      const ctLog: CTLog = await initializeCTLog(keyPair);
      expect(ctLog.logID.toString('hex')).toMatch(/^[0-9a-f]{64}$/);
    });

    it('returns the log ID matching the public key', async () => {
      const ctLog: CTLog = await initializeCTLog(keyPair);

      const logID = ctLog.logID.toString('hex');
      const keyDigest = crypto
        .createHash('sha256')
        .update(ctLog.publicKey)
        .digest('hex');
      expect(logID).toMatch(keyDigest);
    });
  });
});
