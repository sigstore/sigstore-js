import { KeyObject } from 'crypto';
import { Bundle } from '../types/bundle';
import { rekor } from '../types/rekor';
import { crypto, json } from '../util';

export function verifyTLogSET(
  bundle: Bundle,
  tlogKeys: Record<string, KeyObject>
): void {
  bundle.verificationData?.tlogEntries.forEach((entry, index) => {
    // Re-create the original Rekor verification payload
    const payload = rekor.toVerificationPayload(bundle, index);

    if (payload.logIndex === 6069991) console.log(payload);
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
