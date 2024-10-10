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
import { crypto, dsse } from '@sigstore/core';

import type { Envelope } from '@sigstore/bundle';
import type { SignatureContent } from '../shared.types';

export class DSSESignatureContent implements SignatureContent {
  private readonly env: Envelope;

  constructor(env: Envelope) {
    this.env = env;
  }

  public compareDigest(digest: Buffer): boolean {
    return crypto.bufferEqual(
      digest,
      crypto.digest('sha256', this.env.payload)
    );
  }

  public compareSignature(signature: Buffer): boolean {
    return crypto.bufferEqual(signature, this.signature);
  }

  public verifySignature(key: crypto.KeyObject): boolean {
    return crypto.verify(this.preAuthEncoding, key, this.signature);
  }

  public get signature(): Buffer {
    return this.env.signatures.length > 0
      ? this.env.signatures[0].sig
      : Buffer.from('');
  }

  // DSSE Pre-Authentication Encoding
  private get preAuthEncoding(): Buffer {
    return dsse.preAuthEncoding(this.env.payloadType, this.env.payload);
  }
}
