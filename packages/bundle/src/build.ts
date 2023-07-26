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
import { HashAlgorithm } from '@sigstore/protobuf-specs';
import { BUNDLE_V02_MEDIA_TYPE } from './bundle';

import type { Envelope, Signature } from '@sigstore/protobuf-specs';
import type {
  Bundle,
  BundleWithDsseEnvelope,
  BundleWithMessageSignature,
} from './bundle';

// Helper functions for assembling the parts of a Sigstore bundle

type VerificationMaterialOptions = {
  certificate?: Buffer;
  keyHint?: string;
};

type MessageSignatureBundleOptions = {
  digest: Buffer;
  signature: Buffer;
} & VerificationMaterialOptions;

type DSSEBundleOptions = {
  artifact: Buffer;
  artifactType: string;
  signature: Buffer;
} & VerificationMaterialOptions;

// Message signature bundle - $case: 'messageSignature'
export function toMessageSignatureBundle(
  options: MessageSignatureBundleOptions
): BundleWithMessageSignature {
  return {
    mediaType: BUNDLE_V02_MEDIA_TYPE,
    content: {
      $case: 'messageSignature',
      messageSignature: {
        messageDigest: {
          algorithm: HashAlgorithm.SHA2_256,
          digest: options.digest,
        },
        signature: options.signature,
      },
    },
    verificationMaterial: toVerificationMaterial(options),
  };
}

// DSSE envelope bundle - $case: 'dsseEnvelope'

export function toDSSEBundle(
  options: DSSEBundleOptions
): BundleWithDsseEnvelope {
  return {
    mediaType: BUNDLE_V02_MEDIA_TYPE,
    content: {
      $case: 'dsseEnvelope',
      dsseEnvelope: toEnvelope(options),
    },
    verificationMaterial: toVerificationMaterial(options),
  };
}

function toEnvelope(options: DSSEBundleOptions): Envelope {
  return {
    payloadType: options.artifactType,
    payload: options.artifact,
    signatures: [toSignature(options)],
  };
}

function toSignature(options: DSSEBundleOptions): Signature {
  return {
    keyid: options.keyHint || '',
    sig: options.signature,
  };
}

// Verification material

function toVerificationMaterial(
  options: VerificationMaterialOptions
): Bundle['verificationMaterial'] {
  return {
    content: toKeyContent(options),
    tlogEntries: [],
    timestampVerificationData: { rfc3161Timestamps: [] },
  };
}

function toKeyContent(
  options: VerificationMaterialOptions
): Bundle['verificationMaterial']['content'] {
  if (options.certificate) {
    return {
      $case: 'x509CertificateChain',
      x509CertificateChain: {
        certificates: [{ rawBytes: options.certificate }],
      },
    };
  } else {
    return {
      $case: 'publicKey',
      publicKey: {
        hint: options.keyHint || '',
      },
    };
  }
}
