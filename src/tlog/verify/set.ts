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
import * as sigstore from '../../types/sigstore';
import { crypto, json } from '../../util';

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
  entry: sigstore.VerifiableTransparencyLogEntry,
  tlogs: sigstore.TransparencyLogInstance[]
): boolean {
  // Filter the list of tlog instances to only those which might be able to
  // verify the SET
  const validTLogs = filterTLogInstances(
    tlogs,
    entry.logId.keyId,
    entry.integratedTime
  );

  // Check to see if we can verify the SET against any of the valid tlogs
  return validTLogs.some((tlog) => {
    if (!tlog.publicKey?.rawBytes) {
      return false;
    }

    const publicKey = crypto.createPublicKey(tlog.publicKey.rawBytes);

    // Re-create the original Rekor verification payload
    const payload = toVerificationPayload(entry);

    // Canonicalize the payload and turn into a buffer for verification
    const data = Buffer.from(json.canonicalize(payload), 'utf8');

    // Extract the SET from the tlog entry
    const signature = entry.inclusionPromise.signedEntryTimestamp;

    return crypto.verifyBlob(data, publicKey, signature);
  });
}

// Returns a properly formatted "VerificationPayload" for one of the
// transaction log entires in the given bundle which can be used for SET
// verification.
function toVerificationPayload(
  entry: sigstore.VerifiableTransparencyLogEntry
): VerificationPayload {
  const { integratedTime, logIndex, logId, canonicalizedBody } = entry;

  return {
    body: canonicalizedBody.toString('base64'),
    integratedTime: Number(integratedTime),
    logIndex: Number(logIndex),
    logID: logId.keyId.toString('hex'),
  };
}

// Filter the list of tlog instances to only those which match the given log
// ID and have public keys which are valid for the given integrated time.
function filterTLogInstances(
  tlogInstances: sigstore.TransparencyLogInstance[],
  logID: Buffer,
  integratedTime: string
): sigstore.TransparencyLogInstance[] {
  const targetDate = new Date(Number(integratedTime) * 1000);

  return tlogInstances.filter((tlog) => {
    // If the log IDs don't match, we can't use this tlog
    if (!tlog.logId?.keyId.equals(logID)) {
      return false;
    }

    // If the tlog doesn't have a public key, we can't use it
    const publicKey = tlog.publicKey;
    if (publicKey === undefined) {
      return false;
    }

    // If the tlog doesn't have a rawBytes field, we can't use it
    if (publicKey.rawBytes === undefined) {
      return false;
    }

    // If the tlog doesn't have a validFor field, we don't need to check it
    if (publicKey.validFor === undefined) {
      return true;
    }

    // Check that the integrated time is within the validFor range
    return (
      publicKey.validFor.start &&
      publicKey.validFor.start <= targetDate &&
      (!publicKey.validFor.end || targetDate <= publicKey.validFor.end)
    );
  });
}
