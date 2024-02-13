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
import type {
  Bundle as ProtoBundle,
  InclusionProof as ProtoInclusionProof,
  MessageSignature as ProtoMessageSignature,
  TransparencyLogEntry as ProtoTransparencyLogEntry,
  VerificationMaterial as ProtoVerificationMaterial,
} from '@sigstore/protobuf-specs';
import type { WithRequired } from './utility';

export const BUNDLE_V01_MEDIA_TYPE =
  'application/vnd.dev.sigstore.bundle+json;version=0.1';

export const BUNDLE_V02_MEDIA_TYPE =
  'application/vnd.dev.sigstore.bundle+json;version=0.2';

export const BUNDLE_V03_MEDIA_TYPE =
  'application/vnd.dev.sigstore.bundle+json;version=0.3';

// Extract types that are not explicitly defined in the protobuf specs.
type DsseEnvelopeContent = Extract<
  ProtoBundle['content'],
  { $case: 'dsseEnvelope' }
>;
type MessageSignatureContent = Extract<
  ProtoBundle['content'],
  { $case: 'messageSignature' }
>;

// Narrowed types with required fields marked as such.
export type MessageSignature = WithRequired<
  ProtoMessageSignature,
  'messageDigest'
>;

export type VerificationMaterial = WithRequired<
  ProtoVerificationMaterial,
  'content'
>;

export type TransparencyLogEntry = WithRequired<
  ProtoTransparencyLogEntry,
  'logId' | 'kindVersion'
>;

export type InclusionProof = WithRequired<ProtoInclusionProof, 'checkpoint'>;

export type TLogEntryWithInclusionPromise = WithRequired<
  TransparencyLogEntry,
  'inclusionPromise'
>;

export type TLogEntryWithInclusionProof = TransparencyLogEntry & {
  inclusionProof: InclusionProof;
};

// Common type shared by v0.1 and v0.2 of the Sigstore bundle format with all
// required fields populated.
export type Bundle = ProtoBundle & {
  verificationMaterial: VerificationMaterial & {
    tlogEntries: TransparencyLogEntry[];
  };
  content:
    | (MessageSignatureContent & { messageSignature: MessageSignature })
    | DsseEnvelopeContent;
};

// Version 0.1 of the Sigstore bundle format with all required fields populated.
// Ensures inclusion promise is present in each transparency log entry.
export type BundleV01 = Bundle & {
  verificationMaterial: Bundle['verificationMaterial'] & {
    tlogEntries: TLogEntryWithInclusionPromise[];
  };
};

// Version 0.2 of the Sigstore bundle format with all required fields populated.
// Ensures inclusion proof is present in each transparency log entry.
export type BundleLatest = Bundle & {
  verificationMaterial: Bundle['verificationMaterial'] & {
    tlogEntries: TLogEntryWithInclusionProof[];
  };
};

// Bundle variants with specific content types.
export type BundleWithCertificateChain = Bundle & {
  verificationMaterial: Bundle['verificationMaterial'] & {
    content: Extract<
      VerificationMaterial['content'],
      { $case: 'x509CertificateChain' }
    >;
  };
};

export type BundleWithPublicKey = Bundle & {
  verificationMaterial: Bundle['verificationMaterial'] & {
    content: Extract<VerificationMaterial['content'], { $case: 'publicKey' }>;
  };
};

export type BundleWithMessageSignature = Bundle & {
  content: Extract<Bundle['content'], { $case: 'messageSignature' }>;
};

export type BundleWithDsseEnvelope = Bundle & {
  content: Extract<Bundle['content'], { $case: 'dsseEnvelope' }>;
};

// Type guards for bundle variants.
export function isBundleWithCertificateChain(
  b: Bundle
): b is BundleWithCertificateChain {
  return b.verificationMaterial.content.$case === 'x509CertificateChain';
}

export function isBundleWithPublicKey(b: Bundle): b is BundleWithPublicKey {
  return b.verificationMaterial.content.$case === 'publicKey';
}

export function isBundleWithMessageSignature(
  b: Bundle
): b is BundleWithMessageSignature {
  return b.content.$case === 'messageSignature';
}

export function isBundleWithDsseEnvelope(
  b: Bundle
): b is BundleWithDsseEnvelope {
  return b.content.$case === 'dsseEnvelope';
}
