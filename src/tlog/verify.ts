import { KeyObject } from 'crypto';
import { Bundle } from '../types/bundle';
import { rekor } from '../types/rekor';
import { crypto, json } from '../util';

export function verifyTLogSET(
  bundle: Bundle,
  tlogKeys: Record<string, KeyObject>
): boolean {
  const payload = rekor.toVerificationPayload(bundle);
  const publicKey = tlogKeys[payload.logID];
  if (!publicKey) {
    throw new Error('No public key found for logID: ' + payload.logID);
  }

  const signature =
    bundle.verificationData?.tlogEntries[0].inclusionPromise
      ?.signedEntryTimestamp;
  if (!signature) {
    throw new Error('No signature found in bundle');
  }

  // Canonicalize the payload and turn into a buffer
  const data = Buffer.from(json.canonicalize(payload), 'utf8');

  return crypto.verifyBlob(data, publicKey, signature);
}
