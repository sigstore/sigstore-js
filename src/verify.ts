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
import { KeyLike } from 'crypto';
import { SigstoreDSSEBundle } from './bundle';
import { Rekor } from './client';
import * as crypto from './crypto';
import * as enc from './encoding';
import { dssePreAuthEncoding } from './util';

export interface VerifyOptions {
  rekor: Rekor;
}

export class Verifier {
  private rekor: Rekor;

  constructor(options: VerifyOptions) {
    this.rekor = options.rekor;
  }

  public async verify(
    payload: Buffer,
    signature: string,
    certificate: KeyLike
  ): Promise<boolean> {
    signature = signature.trim();

    return crypto.verifyBlob(certificate, payload, signature);
  }

  public async verifyDSSE(bundle: SigstoreDSSEBundle): Promise<boolean> {
    const payloadType = bundle.attestation.payloadType;
    const payload = Buffer.from(bundle.attestation.payload, 'base64');
    const paeBuffer = dssePreAuthEncoding(payloadType, payload);

    if (bundle.attestation.signatures.length < 1) {
      throw new Error('No signatures found in bundle');
    }

    // TODO: Do we need to handle multiple signatures?
    const signature = bundle.attestation.signatures[0].sig;
    const certificate = enc.base64Decode(bundle.certificate);

    return crypto.verifyBlob(certificate, paeBuffer, signature);
  }

  // TODO: come back and clean this up. Currently unused but may be useful when
  // we introduce verification against the Rekor log.
  private async lookupCertificate(
    payload: Buffer,
    signature: string
  ): Promise<KeyLike | undefined> {
    // Calculate artifact digest
    const digest = crypto.hash(payload);

    // Look-up Rekor entries by artifact digest
    const uuids = await this.rekor.searchIndex({ hash: `sha256:${digest}` });

    let b64Cert;
    // Find Rekor entry with matching artifact signature
    // TODO: purposefully doing this lookup serially for now -- consider parallelizing
    for (const uuid of uuids) {
      const entry = await this.rekor.getEntry(uuid);
      const body = JSON.parse(enc.base64Decode(entry.body));

      if (body.spec.signature.content == signature) {
        b64Cert = body.spec.signature.publicKey.content;
        break;
      }
    }

    // If we have a cert here it means we found a matching entry
    if (b64Cert) {
      return enc.base64Decode(b64Cert);
    }
  }
}
