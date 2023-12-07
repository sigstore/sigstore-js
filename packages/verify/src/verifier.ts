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
import { isDeepStrictEqual } from 'util';
import { PolicyError, VerificationError } from './error';
import { verifyCertificate, verifyPublicKey } from './key';
import { verifyExtensions, verifySubjectAlternativeName } from './policy';
import { verifyTLogTimestamp, verifyTSATimestamp } from './timestamp';
import { verifyTLogBody } from './tlog';

import type { CertificateIdentity, SignedEntity, Signer } from './shared.types';
import type { TrustMaterial } from './trust';

export type VerifierOptions = {
  tlogThreshold?: number;
  ctlogThreshold?: number;
  tsaThreshold?: number;
};

export class Verifier {
  private trustMaterial: TrustMaterial;
  private options: Required<VerifierOptions>;

  constructor(trustMaterial: TrustMaterial, options: VerifierOptions = {}) {
    this.trustMaterial = trustMaterial;
    this.options = {
      ctlogThreshold: options.ctlogThreshold ?? 1,
      tlogThreshold: options.tlogThreshold ?? 1,
      tsaThreshold: options.tsaThreshold ?? 0,
    };
  }

  public verify(
    entity: SignedEntity,
    policy?: Required<CertificateIdentity>
  ): Signer {
    const timestamps = this.verifyTimestamps(entity);
    const signer = this.verifySigningKey(entity, timestamps);
    this.verifyTLogs(entity);
    this.verifySignature(entity, signer);

    if (policy) {
      this.verifyPolicy(signer, policy);
    }

    return signer;
  }

  // Checks that all of the timestamps in the entity are valid and returns them
  private verifyTimestamps(entity: SignedEntity): Date[] {
    let tlogCount = 0;
    let tsaCount = 0;

    const timestamps = entity.timestamps.map((timestamp) => {
      switch (timestamp.$case) {
        /* istanbul ignore next - implement this*/
        case 'timestamp-authority':
          tsaCount++;
          return verifyTSATimestamp(
            timestamp.timestamp,
            this.trustMaterial.timestampAuthorities
          );
        case 'transparency-log':
          tlogCount++;
          return verifyTLogTimestamp(
            timestamp.tlogEntry,
            this.trustMaterial.tlogs
          );
      }
    });

    // Check for duplicate timestamps
    if (containsDupes(timestamps)) {
      throw new VerificationError({
        code: 'TIMESTAMP_ERROR',
        message: 'duplicate timestamp',
      });
    }

    if (tlogCount < this.options.tlogThreshold) {
      throw new VerificationError({
        code: 'TIMESTAMP_ERROR',
        message: `expected ${this.options.tlogThreshold} tlog timestamps, got ${tlogCount}`,
      });
    }

    if (tsaCount < this.options.tsaThreshold) {
      throw new VerificationError({
        code: 'TIMESTAMP_ERROR',
        message: `expected ${this.options.tsaThreshold} tsa timestamps, got ${tsaCount}`,
      });
    }

    return timestamps.map((t) => t.timestamp);
  }

  // Checks that the signing key is valid for all of the the supplied timestamps
  // and returns the signer.
  private verifySigningKey({ key }: SignedEntity, timestamps: Date[]): Signer {
    switch (key.$case) {
      case 'public-key': {
        return verifyPublicKey(key.hint, timestamps, this.trustMaterial);
      }
      case 'certificate': {
        const result = verifyCertificate(
          key.certificate,
          timestamps,
          this.trustMaterial
        );

        /* istanbul ignore next - no fixture */
        if (containsDupes(result.scts)) {
          throw new VerificationError({
            code: 'CERTIFICATE_ERROR',
            message: 'duplicate SCT',
          });
        }

        if (result.scts.length < this.options.ctlogThreshold) {
          throw new VerificationError({
            code: 'CERTIFICATE_ERROR',
            message: `expected ${this.options.ctlogThreshold} SCTs, got ${result.scts.length}`,
          });
        }

        return result.signer;
      }
    }
  }

  // Checks that the tlog entries are valid for the supplied content
  private verifyTLogs({ signature: content, tlogEntries }: SignedEntity): void {
    tlogEntries.forEach((entry) => verifyTLogBody(entry, content));
  }

  // Checks that the signature is valid for the supplied content
  private verifySignature(entity: SignedEntity, signer: Signer): void {
    if (!entity.signature.verifySignature(signer.key)) {
      throw new VerificationError({
        code: 'SIGNATURE_ERROR',
        message: 'signature verification failed',
      });
    }
  }

  private verifyPolicy(signer: Signer, policy: Required<CertificateIdentity>) {
    if (!signer.identity) {
      throw new PolicyError({
        code: 'UNTRUSTED_SIGNER_ERROR',
        message: 'no signer identity',
      });
    }

    // Check the subject alternative name of the signer matches the policy
    verifySubjectAlternativeName(
      policy.subjectAlternativeName,
      signer.identity.subjectAlternativeName
    );

    // Check that the extensions of the signer match the policy
    verifyExtensions(policy.extensions, signer.identity.extensions);
  }
}

// Checks for duplicate items in the array. Objects are compared using
// deep equality.
function containsDupes(arr: unknown[]): boolean {
  for (let i = 0; i < arr.length; i++) {
    for (let j = i + 1; j < arr.length; j++) {
      if (isDeepStrictEqual(arr[i], arr[j])) {
        return true;
      }
    }
  }

  return false;
}
