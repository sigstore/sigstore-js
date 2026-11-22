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
import crypto, { BinaryLike } from 'crypto';
import { isValidEd25519Key, isValidEd25519Signature } from './ed25519';
export type { KeyObject } from 'crypto';

export function createPublicKey(
  key: string | Buffer,
  type: 'spki' | 'pkcs1' = 'spki'
): crypto.KeyObject {
  let keyObject: crypto.KeyObject;
  if (typeof key === 'string') {
    if (key.startsWith('-----')) {
      keyObject = crypto.createPublicKey(key);
    } else {
      keyObject = crypto.createPublicKey({
        key: Buffer.from(key, 'base64'),
        format: 'der',
        type: type,
      });
    }
  } else {
    keyObject = crypto.createPublicKey({ key, format: 'der', type: type });
  }

  assertValidEd25519Key(keyObject);
  return keyObject;
}

export function digest(algorithm: string, ...data: BinaryLike[]): Buffer {
  const hash = crypto.createHash(algorithm);
  for (const d of data) {
    if (typeof d === 'string' || ArrayBuffer.isView(d)) {
      hash.update(d);
    } else {
      hash.update(new Uint8Array(d));
    }
  }
  return hash.digest();
}

export function verify(
  data: Buffer,
  key: crypto.KeyLike,
  signature: Buffer,
  algorithm?: string
): boolean {
  // The try/catch is to work around an issue in Node 14.x where verify throws
  // an error in some scenarios if the signature is invalid.
  try {
    const keyObject =
      key instanceof crypto.KeyObject ? key : crypto.createPublicKey(key);
    // Keys may be constructed outside of createPublicKey, so the Ed25519 point
    // checks are repeated here.
    if (!isValidEd25519Key(keyObject)) {
      return false;
    }
    if (
      keyObject.asymmetricKeyType === 'ed25519' &&
      !isValidEd25519Signature(signature)
    ) {
      return false;
    }

    let verificationAlgorithm = algorithm;
    if (verificationAlgorithm === undefined) {
      const keyType = keyObject.asymmetricKeyType;
      // Preserve key-specific defaults for EdDSA and restricted RSA-PSS keys.
      if (keyType === 'ec' || keyType === 'rsa') {
        verificationAlgorithm = 'sha256';
      }
    }

    return crypto.verify(verificationAlgorithm, data, keyObject, signature);
  } catch (e) {
    /* istanbul ignore next */
    return false;
  }
}

export function bufferEqual(a: Buffer, b: Buffer): boolean {
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    /* istanbul ignore next */
    return false;
  }
}

// RFC 8032 verification does not require the public key to be a canonically
// encoded point of large order, and crypto backends differ in whether they
// accept such keys. They are refused here so the result does not depend on the
// backend.
function assertValidEd25519Key(key: crypto.KeyObject): void {
  if (!isValidEd25519Key(key)) {
    throw new Error(
      'invalid Ed25519 public key: small-order, non-canonical or off-curve point'
    );
  }
}
