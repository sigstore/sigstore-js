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
import { createPublicKey, KeyObject } from 'crypto';
import { crypto } from '../util';

// Returns the set of trusted log keys which can be used to verify the
// Signed Entry Timestamps in the log.
export function getKeys(): Record<string, KeyObject> {
  // TODO: This should be be loaded via TUF
  const pem = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`

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
