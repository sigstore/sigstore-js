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
import { KeyObject } from 'crypto';
import { Bundle } from '../types/bundle';
import { crypto, json } from '../util';
import { rekor } from './format';

export function verifyTLogSET(
  bundle: Bundle,
  tlogKeys: Record<string, KeyObject>
): void {
  bundle.verificationData?.tlogEntries.forEach((entry, index) => {
    // Re-create the original Rekor verification payload
    const payload = rekor.toVerificationPayload(bundle, index);

    // Canonicalize the payload and turn into a buffer for verification
    const data = Buffer.from(json.canonicalize(payload), 'utf8');

    // Find the public key for the transaction log which generated the SET
    const publicKey = tlogKeys[payload.logID];
    if (!publicKey) {
      throw new Error('no key found for logID: ' + payload.logID);
    }

    // Extract the SET from the tlog entry
    const signature = entry.inclusionPromise?.signedEntryTimestamp;
    if (!signature) {
      throw new Error('no SET found in bundle');
    }

    if (!crypto.verifyBlob(data, publicKey, signature)) {
      throw new Error('transparency log SET verification failed');
    }
  });
}
