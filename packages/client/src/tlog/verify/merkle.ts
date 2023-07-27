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
import crypto from 'crypto';
import { VerificationError } from '../../error';

import type { TLogEntryWithInclusionProof } from '@sigstore/bundle';

const RFC6962_LEAF_HASH_PREFIX = Buffer.from([0x00]);
const RFC6962_NODE_HASH_PREFIX = Buffer.from([0x01]);

export function verifyMerkleInclusion(
  entry: TLogEntryWithInclusionProof
): boolean {
  const inclusionProof = entry.inclusionProof;
  const logIndex = BigInt(inclusionProof.logIndex);
  const treeSize = BigInt(inclusionProof.treeSize);

  if (logIndex < 0n || logIndex >= treeSize) {
    throw new VerificationError('invalid inclusion proof index');
  }

  // Figure out which subset of hashes corresponds to the inner and border
  // nodes
  const { inner, border } = decompInclProof(logIndex, treeSize);

  if (inclusionProof.hashes.length !== inner + border) {
    throw new VerificationError('invalid inclusion proof length');
  }

  const innerHashes = inclusionProof.hashes.slice(0, inner);
  const borderHashes = inclusionProof.hashes.slice(inner);

  // The entry's hash is the leaf hash
  const leafHash = hashLeaf(entry.canonicalizedBody);

  // Chain the hashes belonging to the inner and border portions
  const calculatedHash = chainBorderRight(
    chainInner(leafHash, innerHashes, logIndex),
    borderHashes
  );

  // Calculated hash should match the root hash in the inclusion proof
  return bufferEqual(calculatedHash, inclusionProof.rootHash);
}

// Breaks down inclusion proof for a leaf at the specified index in a tree of
// the specified size. The split point is where paths to the index leaf and
// the (size - 1) leaf diverge. Returns lengths of the bottom and upper proof
// parts.
function decompInclProof(
  index: bigint,
  size: bigint
): { inner: number; border: number } {
  const inner = innerProofSize(index, size);
  const border = onesCount(index >> BigInt(inner));
  return { inner, border };
}

// Computes a subtree hash for a node on or below the tree's right border.
// Assumes the provided proof hashes are ordered from lower to higher levels
// and seed is the initial hash of the node specified by the index.
function chainInner(seed: Buffer, hashes: Buffer[], index: bigint): Buffer {
  return hashes.reduce((acc, h, i) => {
    if ((index >> BigInt(i)) & BigInt(1)) {
      return hashChildren(h, acc);
    } else {
      return hashChildren(acc, h);
    }
  }, seed);
}

// Computes a subtree hash for nodes along the tree's right border.
function chainBorderRight(seed: Buffer, hashes: Buffer[]): Buffer {
  return hashes.reduce((acc, h) => hashChildren(h, acc), seed);
}

function innerProofSize(index: bigint, size: bigint): number {
  return bitLength(index ^ (size - BigInt(1)));
}

// Counts the number of ones in the binary representation of the given number.
// https://en.wikipedia.org/wiki/Hamming_weight
function onesCount(x: bigint): number {
  return x.toString(2).split('1').length - 1;
}

// Returns the number of bits necessary to represent an integer in binary.
function bitLength(n: bigint): number {
  if (n === 0n) {
    return 0;
  }
  return n.toString(2).length;
}

// Hashing logic according to RFC6962.
// https://datatracker.ietf.org/doc/html/rfc6962#section-2
function hashChildren(left: Buffer, right: Buffer): Buffer {
  const hasher = crypto.createHash('sha256');
  hasher.update(RFC6962_NODE_HASH_PREFIX);
  hasher.update(left);
  hasher.update(right);
  return hasher.digest();
}

function hashLeaf(leaf: Buffer): Buffer {
  const hasher = crypto.createHash('sha256');
  hasher.update(RFC6962_LEAF_HASH_PREFIX);
  hasher.update(leaf);
  return hasher.digest();
}

function bufferEqual(a: Buffer, b: Buffer): boolean {
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    /* istanbul ignore next */
    return false;
  }
}
