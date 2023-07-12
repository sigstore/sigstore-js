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
import { BUNDLE_V01_MEDIA_TYPE } from '@sigstore/bundle';
import { HashAlgorithm } from '@sigstore/protobuf-specs';
import { crypto, pem } from '../util';

import type * as sigstore from '@sigstore/bundle';
import type { KeyMaterial, Signature } from '../signer';
import type { Artifact } from './base';

// Helper functions for assembling the parts of a Sigstore bundle

// Message signature bundle - $case: 'messageSignature'
export function toMessageSignatureBundle(
  artifact: Artifact,
  signature: Signature
): sigstore.Bundle {
  const digest = crypto.hash(artifact.data);

  return {
    mediaType: BUNDLE_V01_MEDIA_TYPE,
    content: {
      $case: 'messageSignature',
      messageSignature: {
        messageDigest: {
          algorithm: HashAlgorithm.SHA2_256,
          digest: digest,
        },
        signature: signature.signature,
      },
    },
    verificationMaterial: toVerificationMaterial(signature.key),
  };
}

// DSSE envelope bundle - $case: 'dsseEnvelope'
export function toDSSEBundle(
  artifact: Required<Artifact>,
  signature: Signature
): sigstore.Bundle {
  return {
    mediaType: BUNDLE_V01_MEDIA_TYPE,
    content: {
      $case: 'dsseEnvelope',
      dsseEnvelope: toEnvelope(artifact, signature),
    },
    verificationMaterial: toVerificationMaterial(signature.key),
  };
}

function toEnvelope(
  artifact: Required<Artifact>,
  signature: Signature
): sigstore.Envelope {
  return {
    payloadType: artifact.type,
    payload: artifact.data,
    signatures: [toSignature(signature)],
  };
}

function toSignature(signature: Signature): sigstore.Signature {
  return {
    keyid: toKeyID(signature),
    sig: signature.signature,
  };
}

function toKeyID(signature: Signature): string {
  switch (signature.key.$case) {
    case 'publicKey':
      return signature.key.hint || '';
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
