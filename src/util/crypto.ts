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
import crypto, { BinaryLike, KeyLike, KeyPairKeyObjectResult } from 'crypto';

const EC_KEYPAIR_TYPE = 'ec';
const P256_CURVE = 'P-256';
const SHA256_ALGORITHM = 'sha256';

export function generateKeyPair(): KeyPairKeyObjectResult {
  return crypto.generateKeyPairSync(EC_KEYPAIR_TYPE, {
    namedCurve: P256_CURVE,
  });
}

export function signBlob(
  data: NodeJS.ArrayBufferView,
  privateKey: KeyLike
): Buffer {
  return crypto.sign(null, data, privateKey);
}

export function verifyBlob(
  data: Buffer,
  key: KeyLike,
  signature: Buffer
): boolean {
  return crypto.verify(null, data, key, signature);
}

export function hash(data: BinaryLike): Buffer {
  const hash = crypto.createHash(SHA256_ALGORITHM);
  return hash.update(data).digest();
}

export function randomBytes(count: number): Buffer {
  return crypto.randomBytes(count);
}
