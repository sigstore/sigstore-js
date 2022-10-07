import { createPublicKey, KeyObject } from 'crypto';
import { crypto } from '../util';
import fs from 'fs';

export function getKeys(): Record<string, KeyObject> {
  const pem = fs.readFileSync('store/rekor.pub', 'utf-8');
  const key = createPublicKey(pem);
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
