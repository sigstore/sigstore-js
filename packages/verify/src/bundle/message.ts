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
import { crypto } from '@sigstore/core';
import { HashAlgorithm } from '@sigstore/protobuf-specs';

import type { MessageSignature } from '@sigstore/bundle';
import type { SignatureContent } from '../shared.types';

// Map from the Sigstore protobuf HashAlgorithm enum to
// the string values used by the Node.js crypto module.
const HASH_ALGORITHM_MAP: Record<HashAlgorithm, string> = {
  [HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED]: 'sha256',
  [HashAlgorithm.SHA2_256]: 'sha256',
  [HashAlgorithm.SHA2_384]: 'sha384',
  [HashAlgorithm.SHA2_512]: 'sha512',
  [HashAlgorithm.SHA3_256]: 'sha3-256',
  [HashAlgorithm.SHA3_384]: 'sha3-384',
};

export class MessageSignatureContent implements SignatureContent {
  public readonly signature: Buffer;
  private readonly messageDigest: Buffer;
  private readonly artifact: Buffer;
  private readonly hashAlgorithm: string;

  constructor(messageSignature: MessageSignature, artifact: Buffer) {
    this.signature = messageSignature.signature;
    this.messageDigest = messageSignature.messageDigest.digest;
    this.artifact = artifact;
    this.hashAlgorithm =
      HASH_ALGORITHM_MAP[messageSignature.messageDigest.algorithm] ??
      /* istanbul ignore next */ 'sha256';
  }

  public compareSignature(signature: Buffer): boolean {
    return crypto.bufferEqual(signature, this.signature);
  }

  public compareDigest(digest: Buffer): boolean {
    return crypto.bufferEqual(digest, this.messageDigest);
  }

  public verifySignature(key: crypto.KeyObject): boolean {
    return crypto.verify(
      this.artifact,
      key,
      this.signature,
      this.hashAlgorithm
    );
  }
}
