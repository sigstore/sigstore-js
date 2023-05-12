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

import crypto from 'crypto';

const RFC6962LeafHashPrefix = Buffer.from([0x00]);
const RFC6962NodeHashPrefix = Buffer.from([0x01]);

// Implements Merkle Tree Hash logic according to RFC6962.
// https://datatracker.ietf.org/doc/html/rfc6962#section-2
export class Hasher {
  private algorithm: string;

  constructor(algorithm = 'sha256') {
    this.algorithm = algorithm;
  }

  public size(): number {
    return crypto.createHash(this.algorithm).digest().length;
  }

  public hashLeaf(leaf: Buffer): Buffer {
    const hasher = crypto.createHash(this.algorithm);
    hasher.update(RFC6962LeafHashPrefix);
    hasher.update(leaf);
    return hasher.digest();
  }

  public hashChildren(l: Buffer, r: Buffer): Buffer {
    const hasher = crypto.createHash(this.algorithm);
    hasher.update(RFC6962NodeHashPrefix);
    hasher.update(l);
    hasher.update(r);
    return hasher.digest();
  }
}
