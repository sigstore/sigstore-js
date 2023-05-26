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
import { HashAlgorithm } from '../types/sigstore';
import { crypto, pem } from '../util';

import type { Endorsement, KeyMaterial } from '../signatory';
import type * as sigstore from '../types/sigstore';
import type { Artifact } from './notary';

// Helper functions for assembling the parts of a Sigstore bundle

const BUNDLE_MEDIA_TYPE =
  'application/vnd.dev.sigstore.bundle+json;version=0.1';

// Message signature bundle - $case: 'messageSignature'
export function toMessageSignatureBundle(
  artifact: Artifact,
  endorsement: Endorsement
): sigstore.Bundle {
  const digest = crypto.hash(artifact.data);

  return {
    mediaType: BUNDLE_MEDIA_TYPE,
    content: {
      $case: 'messageSignature',
      messageSignature: {
        messageDigest: {
          algorithm: HashAlgorithm.SHA2_256,
          digest: digest,
        },
        signature: endorsement.signature,
      },
    },
    verificationMaterial: toVerificationMaterial(endorsement.key),
  };
}

// DSSE envelope bundle - $case: 'dsseEnvelope'
export function toDSSEBundle(
  artifact: Required<Artifact>,
  endorsement: Endorsement
): sigstore.Bundle {
  return {
    mediaType: BUNDLE_MEDIA_TYPE,
    content: {
      $case: 'dsseEnvelope',
      dsseEnvelope: toEnvelope(artifact, endorsement),
    },
    verificationMaterial: toVerificationMaterial(endorsement.key),
  };
}

function toEnvelope(
  artifact: Required<Artifact>,
  endorsement: Endorsement
): sigstore.Envelope {
  return {
    payloadType: artifact.type,
    payload: artifact.data,
    signatures: [toSignature(endorsement)],
  };
}

function toSignature(endorsement: Endorsement): sigstore.Signature {
  return {
    keyid: toKeyID(endorsement),
    sig: endorsement.signature,
  };
}

function toKeyID(endorsement: Endorsement): string {
  switch (endorsement.key.$case) {
    case 'publicKey':
      return endorsement.key.hint || '';
    case 'x509Certificate':
      return '';
  }
}

// Verification material

function toVerificationMaterial(
  key: KeyMaterial
): sigstore.Bundle['verificationMaterial'] {
  return {
    content: toKeyContent(key),
    tlogEntries: [],
    timestampVerificationData: { rfc3161Timestamps: [] },
  };
}

function toKeyContent(
  key: KeyMaterial
): sigstore.Bundle['verificationMaterial']['content'] {
  switch (key.$case) {
    case 'publicKey':
      return {
        $case: 'publicKey',
        publicKey: {
          hint: key.hint || '',
        },
      };
    case 'x509Certificate':
      return {
        $case: 'x509CertificateChain',
        x509CertificateChain: {
          certificates: [{ rawBytes: pem.toDER(key.certificate) }],
        },
      };
  }
}
