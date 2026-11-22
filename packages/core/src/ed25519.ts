/*
Copyright 2026 The Sigstore Authors.

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
import type { KeyObject } from 'crypto';

// Ed25519 field prime p = 2^255 - 19 and curve constant d = -121665/121666 mod p
// (RFC 8032, section 5.1).
const ED25519_P = (BigInt(1) << BigInt(255)) - BigInt(19);
export const ED25519_D = mod(
  -BigInt(121665) * modPow(BigInt(121666), ED25519_P - BigInt(2), ED25519_P),
  ED25519_P
);

// y-coordinates of the points of order 1, 2, 4 and 8. With the sign bit
// ignored these cover every canonical small-order encoding.
const ED25519_ORDER_8_Y = BigInt(
  '0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7'
);
const ED25519_SMALL_ORDER_Y = new Set<bigint>([
  BigInt(0),
  BigInt(1),
  ED25519_P - BigInt(1),
  ED25519_ORDER_8_Y,
  ED25519_P - ED25519_ORDER_8_Y,
]);

export function isValidEd25519Key(key: KeyObject): boolean {
  if (key.asymmetricKeyType !== 'ed25519') {
    return true;
  }

  const spki = key.export({ format: 'der', type: 'spki' });
  /* istanbul ignore if */
  if (spki.length !== 44) {
    return false;
  }

  return isValidEd25519Point(spki.subarray(12));
}

export function isValidEd25519Point(encoded: Uint8Array): boolean {
  if (encoded.length !== 32) {
    return false;
  }

  // Little-endian y-coordinate with the x sign bit (bit 255) cleared.
  let y = BigInt(0);
  for (let i = 31; i >= 0; i--) {
    const byte = i === 31 ? encoded[i] & 0x7f : encoded[i];
    y = (y << BigInt(8)) | BigInt(byte);
  }

  // Non-canonical: the encoded y must be reduced mod p.
  if (y >= ED25519_P) {
    return false;
  }

  if (ED25519_SMALL_ORDER_Y.has(y)) {
    return false;
  }

  // On-curve: x^2 = (y^2 - 1) / (d*y^2 + 1) must have a square root, which by
  // Euler's criterion means u/v is zero or (u/v)^((p-1)/2) == 1. u/v is never
  // zero here because y = +/-1 was rejected above.
  const y2 = mod(y * y, ED25519_P);
  const u = mod(y2 - BigInt(1), ED25519_P);
  const v = mod(ED25519_D * y2 + BigInt(1), ED25519_P);
  const x2 = mod(u * modPow(v, ED25519_P - BigInt(2), ED25519_P), ED25519_P);
  return (
    modPow(x2, (ED25519_P - BigInt(1)) / BigInt(2), ED25519_P) === BigInt(1)
  );
}

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= BigInt(0) ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = BigInt(1);
  let b = mod(base, m);
  let e = exp;
  while (e > BigInt(0)) {
    if (e & BigInt(1)) {
      result = (result * b) % m;
    }
    b = (b * b) % m;
    e >>= BigInt(1);
  }
  return result;
}
