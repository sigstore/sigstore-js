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
import { VerificationError } from './error';
import { verifyCertificate, verifyPublicKey } from './key';
import { verifyExtensions, verifySubjectAlternativeName } from './policy';
import { getTLogTimestamp, getTSATimestamp } from './timestamp';
import { verifyTLogBody, verifyTLogInclusion } from './tlog';

import type {
  CertificateIdentity,
  SignedEntity,
  Signer,
  VerificationPolicy,
} from './shared.types';
import type { TrustMaterial } from './trust';

/**
 * Configuration options for the verifier.
 *
 * @public
 */
export interface VerifierOptions {
  /** Minimum number of transparency log entries required for verification */
  tlogThreshold?: number;
  /** Minimum number of certificate transparency log entries required */
  ctlogThreshold?: number;
  /**
   * Minimum number of timestamp authority timestamps required for verification
   * @deprecated Use timestampThreshold instead
   */
  tsaThreshold?: number;
  /** Minimum number of timestamps required for verification */
  timestampThreshold?: number;
}

export class Verifier {
  private trustMaterial: TrustMaterial;
  private options: Required<VerifierOptions>;

  constructor(trustMaterial: TrustMaterial, options: VerifierOptions = {}) {
    this.trustMaterial = trustMaterial;
    this.options = {
      ctlogThreshold: options.ctlogThreshold ?? 1,
      tlogThreshold: options.tlogThreshold ?? 1,
      timestampThreshold:
        options.timestampThreshold ?? options.tsaThreshold ?? 1,
      tsaThreshold: 0,
    };
  }

  public verify(entity: SignedEntity, policy?: VerificationPolicy): Signer {
    const timestamps = this.verifyTimestamps(entity);
    const signer = this.verifySigningKey(entity, timestamps);
    this.verifyTLogs(entity);
    this.verifySignature(entity, signer);

    if (policy) {
      this.verifyPolicy(policy, signer.identity || {});
    }

    return signer;
  }

  // Checks that all of the timestamps in the entity are valid and returns them
  private verifyTimestamps(entity: SignedEntity): Date[] {
    let timestampCount = 0;

    const timestamps = entity.timestamps.map((timestamp) => {
      switch (timestamp.$case) {
        case 'timestamp-authority':
          timestampCount++;
          return getTSATimestamp(
            timestamp.timestamp,
            entity.signature.signature,
            this.trustMaterial.timestampAuthorities
          );
        case 'transparency-log':
          timestampCount++;
          return getTLogTimestamp(timestamp.tlogEntry);
      }
    });

    // Check for duplicate timestamps
    if (containsDupes(timestamps)) {
      throw new VerificationError({
        code: 'TIMESTAMP_ERROR',
        message: 'duplicate timestamp',
      });
    }

    if (timestampCount < this.options.timestampThreshold) {
      throw new VerificationError({
        code: 'TIMESTAMP_ERROR',
        message: `expected ${this.options.timestampThreshold} timestamps, got ${timestampCount}`,
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
    let tlogCount = 0;

    tlogEntries.forEach((entry) => {
      tlogCount++;
      verifyTLogInclusion(entry, this.trustMaterial.tlogs);
      verifyTLogBody(entry, content);
    });

    if (tlogCount < this.options.tlogThreshold) {
      throw new VerificationError({
        code: 'TLOG_ERROR',
        message: `expected ${this.options.tlogThreshold} tlog entries, got ${tlogCount}`,
      });
    }
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

  private verifyPolicy(
    policy: VerificationPolicy,
    identity: CertificateIdentity
  ) {
    // Check the subject alternative name of the signer matches the policy
    /* istanbul ignore else */
    if (policy.subjectAlternativeName) {
      verifySubjectAlternativeName(
        policy.subjectAlternativeName,
        identity.subjectAlternativeName
      );
    }

    // Check that the extensions of the signer match the policy
    /* istanbul ignore else */
    if (policy.extensions) {
      verifyExtensions(policy.extensions, identity.extensions);
    }
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
