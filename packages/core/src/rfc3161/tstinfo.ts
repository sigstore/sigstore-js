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
import { ASN1Obj } from '../asn1';
import * as crypto from '../crypto';
import { SHA2_HASH_ALGOS } from '../oid';
import { RFC3161TimestampVerificationError } from './error';

export class TSTInfo {
  public root: ASN1Obj;

  constructor(asn1: ASN1Obj) {
    this.root = asn1;
  }

  get version(): bigint {
    return this.root.subs[0].toInteger();
  }

  get genTime(): Date {
    return this.root.subs[4].toDate();
  }

  get messageImprintHashAlgorithm(): string {
    const oid = this.messageImprintObj.subs[0].subs[0].toOID();
    return SHA2_HASH_ALGOS[oid];
  }

  get messageImprintHashedMessage(): Buffer {
    return this.messageImprintObj.subs[1].value;
  }

  get raw(): Buffer {
    return this.root.toDER();
  }

  public verify(data: Buffer): void {
    const digest = crypto.digest(this.messageImprintHashAlgorithm, data);
    if (!crypto.bufferEqual(digest, this.messageImprintHashedMessage)) {
      throw new RFC3161TimestampVerificationError(
        'message imprint does not match artifact'
      );
    }
  }

  // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
  private get messageImprintObj(): ASN1Obj {
    return this.root.subs[2];
  }
}
