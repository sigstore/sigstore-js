/*
Copyright 2022 GitHub, Inc

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
import {
  BinaryLike,
  BinaryToTextEncoding,
  createHash,
  createSign,
  createVerify,
  generateKeyPairSync,
  KeyLike,
  KeyPairKeyObjectResult,
  randomBytes as randBytes,
} from 'crypto';

const EC_KEYPAIR_TYPE = 'ec';
const P256_CURVE = 'P-256';
const SHA256_ALGORITHM = 'sha256';
const BASE64_ENCODING = 'base64';

export function generateKeyPair(): KeyPairKeyObjectResult {
  return generateKeyPairSync(EC_KEYPAIR_TYPE, { namedCurve: P256_CURVE });
}

export function signBlob(privateKey: KeyLike, blob: BinaryLike): string {
  const signer = createSign(SHA256_ALGORITHM);
  signer.update(blob);
  signer.end();
  return signer.sign(privateKey, BASE64_ENCODING);
}

export function verifyBlob(
  publicKey: KeyLike,
  blob: BinaryLike,
  signature: string
): boolean {
  const verifier = createVerify(SHA256_ALGORITHM);
  verifier.update(blob);
  verifier.end();
  return verifier.verify(publicKey, signature, BASE64_ENCODING);
}

export function hash(
  blob: BinaryLike,
  encoding: BinaryToTextEncoding = 'hex'
): string {
  const hash = createHash(SHA256_ALGORITHM);
  hash.update(blob);
  return hash.digest(encoding);
}

export function randomBytes(count: number): Buffer {
  return randBytes(count);
}
