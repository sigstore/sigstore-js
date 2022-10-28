import { createPublicKey, KeyObject } from 'crypto';
import fs from 'fs';
import { crypto } from '../util';

export function getKeys(): Record<string, KeyObject> {
  // TODO: This should be be loaded via TUF
  const pem = fs.readFileSync('store/rekor.pub', 'utf-8');
  const key = createPublicKey(pem);

  // Calculate logID from the key
  const logID = getLogID(key);

  const keys = {
    [logID]: key,
  };

  return keys;
}

// Returns the hex-encoded SHA-256 hash of the public key.
function getLogID(key: KeyObject): string {
  const der = key.export({ format: 'der', type: 'spki' });
  return crypto.hash(der).toString('hex');
}
