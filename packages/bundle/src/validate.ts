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
import { BUNDLE_V01_MEDIA_TYPE } from './bundle';
import { ValidationError } from './error';

import type { Bundle as ProtoBundle } from '@sigstore/protobuf-specs';
import type { Bundle, BundleLatest, BundleV01 } from './bundle';

// Performs basic validation of a Sigstore bundle to ensure that all required
// fields are populated. This is not a complete validation of the bundle, but
// rather a check that the bundle is in a valid state to be processed by the
// rest of the code.
export function assertBundle(b: ProtoBundle): asserts b is Bundle {
  const invalidValues: string[] = [];

  // Media type validation
  if (
    b.mediaType === undefined ||
    !b.mediaType.startsWith('application/vnd.dev.sigstore.bundle+json;version=')
  ) {
    invalidValues.push('mediaType');
  }

  // Content-related validation
  if (b.content === undefined) {
    invalidValues.push('content');
  } else {
    switch (b.content.$case) {
      case 'messageSignature':
        if (b.content.messageSignature.messageDigest === undefined) {
          invalidValues.push('content.messageSignature.messageDigest');
        } else {
          if (b.content.messageSignature.messageDigest.digest.length === 0) {
            invalidValues.push('content.messageSignature.messageDigest.digest');
          }
        }

        if (b.content.messageSignature.signature.length === 0) {
          invalidValues.push('content.messageSignature.signature');
        }
        break;
      case 'dsseEnvelope':
        if (b.content.dsseEnvelope.payload.length === 0) {
          invalidValues.push('content.dsseEnvelope.payload');
        }

        if (b.content.dsseEnvelope.signatures.length !== 1) {
          invalidValues.push('content.dsseEnvelope.signatures');
        } else {
          if (b.content.dsseEnvelope.signatures[0].sig.length === 0) {
            invalidValues.push('content.dsseEnvelope.signatures[0].sig');
          }
        }

        break;
    }
  }

  // Verification material-related validation
  if (b.verificationMaterial === undefined) {
    invalidValues.push('verificationMaterial');
  } else {
    if (b.verificationMaterial.content === undefined) {
      invalidValues.push('verificationMaterial.content');
    } else {
      switch (b.verificationMaterial.content.$case) {
        case 'x509CertificateChain':
          if (
            b.verificationMaterial.content.x509CertificateChain.certificates
              .length === 0
          ) {
            invalidValues.push(
              'verificationMaterial.content.x509CertificateChain.certificates'
            );
          }

          b.verificationMaterial.content.x509CertificateChain.certificates.forEach(
            (cert, i) => {
              if (cert.rawBytes.length === 0) {
                invalidValues.push(
                  `verificationMaterial.content.x509CertificateChain.certificates[${i}].rawBytes`
                );
              }
            }
          );
          break;
      }
    }

    if (b.verificationMaterial.tlogEntries === undefined) {
      invalidValues.push('verificationMaterial.tlogEntries');
    } else {
      if (b.verificationMaterial.tlogEntries.length > 0) {
        b.verificationMaterial.tlogEntries.forEach((entry, i) => {
          if (entry.logId === undefined) {
            invalidValues.push(`verificationMaterial.tlogEntries[${i}].logId`);
          }

          if (entry.kindVersion === undefined) {
            invalidValues.push(
              `verificationMaterial.tlogEntries[${i}].kindVersion`
            );
          }
        });
      }
    }
  }

  if (invalidValues.length > 0) {
    throw new ValidationError('invalid bundle', invalidValues);
  }
}

// Asserts that the given bundle conforms to the v0.1 bundle format.
export function assertBundleV01(b: Bundle): asserts b is BundleV01 {
  const invalidValues: string[] = [];

  if (b.mediaType && b.mediaType !== BUNDLE_V01_MEDIA_TYPE) {
    invalidValues.push('mediaType');
  }

  if (
    b.verificationMaterial &&
    b.verificationMaterial.tlogEntries?.length > 0
  ) {
    b.verificationMaterial.tlogEntries.forEach((entry, i) => {
      if (entry.inclusionPromise === undefined) {
        invalidValues.push(
          `verificationMaterial.tlogEntries[${i}].inclusionPromise`
        );
      }
    });
  }

  if (invalidValues.length > 0) {
    throw new ValidationError('invalid v0.1 bundle', invalidValues);
  }
}

// Type guard to determine if Bundle is a v0.1 bundle.
export function isBundleV01(b: Bundle): b is BundleV01 {
  try {
    assertBundleV01(b);
    return true;
  } catch (e) {
    return false;
  }
}

// Asserts that the given bundle conforms to the newest (0.2) bundle format.
export function assertBundleLatest(b: ProtoBundle): asserts b is BundleLatest {
  const invalidValues: string[] = [];

  if (
    b.verificationMaterial &&
    b.verificationMaterial.tlogEntries?.length > 0
  ) {
    b.verificationMaterial.tlogEntries.forEach((entry, i) => {
      if (entry.inclusionProof === undefined) {
        invalidValues.push(
          `verificationMaterial.tlogEntries[${i}].inclusionProof`
        );
      } else {
        if (entry.inclusionProof.checkpoint === undefined) {
          invalidValues.push(
            `verificationMaterial.tlogEntries[${i}].inclusionProof.checkpoint`
          );
        }
      }
    });
  }

  if (invalidValues.length > 0) {
    throw new ValidationError('invalid v0.2 bundle', invalidValues);
  }
}
