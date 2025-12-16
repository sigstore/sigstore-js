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
import { crypto, json } from '@sigstore/core';
import { VerificationError } from '../error';
import { filterTLogAuthorities, TLogAuthority } from '../trust';

import type { TLogEntryWithInclusionPromise } from '@sigstore/bundle';

// Structure over which the tlog SET signature is generated
interface VerificationPayload {
  body: string;
  integratedTime: number;
  logIndex: number;
  logID: string;
}

// Verifies the SET for the given entry against the list of trusted
// transparency logs. Returns true if the SET can be verified against at least
// one of the trusted logs; otherwise, returns false.
export function verifyTLogSET(
  entry: TLogEntryWithInclusionPromise,
  tlogs: TLogAuthority[]
): void {
  // Filter the list of tlog instances to only those which might be able to
  // verify the SET
  const validTLogs = filterTLogAuthorities(tlogs, {
    logID: entry.logId.keyId,
    targetDate: new Date(Number(entry.integratedTime) * 1000),
  });

  // Check to see if we can verify the SET against any of the valid tlogs
  const verified = validTLogs.some((tlog) => {
    // Re-create the original Rekor verification payload
    const payload = toVerificationPayload(entry);

    // Canonicalize the payload and turn into a buffer for verification
    const data = Buffer.from(json.canonicalize(payload), 'utf8');

    // Extract the SET from the tlog entry
    const signature = entry.inclusionPromise.signedEntryTimestamp;

    return crypto.verify(data, tlog.publicKey, signature);
  });

  if (!verified) {
    throw new VerificationError({
      code: 'TLOG_INCLUSION_PROMISE_ERROR',
      message: 'inclusion promise could not be verified',
    });
  }
}

// Returns a properly formatted "VerificationPayload" for one of the
// transaction log entires in the given bundle which can be used for SET
// verification.
function toVerificationPayload(
  entry: TLogEntryWithInclusionPromise
): VerificationPayload {
  const { integratedTime, logIndex, logId, canonicalizedBody } = entry;

  return {
    body: canonicalizedBody.toString('base64'),
    integratedTime: Number(integratedTime),
    logIndex: Number(logIndex),
    logID: logId.keyId.toString('hex'),
  };
}
