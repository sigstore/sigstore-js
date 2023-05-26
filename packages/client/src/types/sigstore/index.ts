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
import { Bundle } from '@sigstore/protobuf-specs';
import { ValidBundle, assertValidBundle } from './validate';

import type {
  ArtifactVerificationOptions,
  TransparencyLogEntry,
  VerificationMaterial,
} from '@sigstore/protobuf-specs';
import type { WithRequired } from '../utility';
import type { SerializedBundle } from './serialized';

// Enums from protobuf-specs
export {
  HashAlgorithm,
  PublicKeyDetails,
  SubjectAlternativeNameType,
} from '@sigstore/protobuf-specs';
// Types from protobuf-specs
export type {
  ArtifactVerificationOptions,
  ArtifactVerificationOptions_CtlogOptions,
  ArtifactVerificationOptions_TlogOptions,
  CertificateAuthority,
  CertificateIdentities,
  CertificateIdentity,
  Envelope,
  MessageSignature,
  ObjectIdentifierValuePair,
  PublicKey,
  PublicKeyIdentifier,
  RFC3161SignedTimestamp,
  Signature,
  SubjectAlternativeName,
  TimestampVerificationData,
  TransparencyLogEntry,
  TransparencyLogInstance,
  TrustedRoot,
  X509Certificate,
  X509CertificateChain,
} from '@sigstore/protobuf-specs';
export type { SerializedBundle, SerializedEnvelope } from './serialized';
export type { ValidBundle as Bundle };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const bundleFromJSON = (obj: any): ValidBundle => {
  const bundle = Bundle.fromJSON(obj);
  assertValidBundle(bundle);
  return bundle;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const bundleToJSON = (bundle: ValidBundle): SerializedBundle => {
  return Bundle.toJSON(bundle) as SerializedBundle;
};

// Subset of sigstore.Bundle that has a certificate chain as part
// of the verification material (as opposed to a public key)
export type BundleWithCertificateChain = ValidBundle & {
  verificationMaterial: VerificationMaterial & {
    content: Extract<
      VerificationMaterial['content'],
      { $case: 'x509CertificateChain' }
    >;
  };
};

// Type guard for narrowing a Bundle to a BundleWithCertificateChain
export function isBundleWithCertificateChain(
  bundle: ValidBundle
): bundle is BundleWithCertificateChain {
  return (
    bundle.verificationMaterial.content !== undefined &&
    bundle.verificationMaterial.content.$case === 'x509CertificateChain'
  );
}

export type RequiredArtifactVerificationOptions = WithRequired<
  ArtifactVerificationOptions,
  'ctlogOptions' | 'tlogOptions'
>;

// Subset of sigstore.ArtifactVerificationOptions that has a
// both ctlogOptions and certificate identities defined
export type CAArtifactVerificationOptions = WithRequired<
  ArtifactVerificationOptions,
  'ctlogOptions'
> & {
  signers?: Extract<
    ArtifactVerificationOptions['signers'],
    { $case: 'certificateIdentities' }
  >;
};

export function isCAVerificationOptions(
  options: ArtifactVerificationOptions
): options is CAArtifactVerificationOptions {
  return (
    options.ctlogOptions !== undefined &&
    (options.signers === undefined ||
      options.signers.$case === 'certificateIdentities')
  );
}

export type VerifiableTransparencyLogEntry = WithRequired<
  TransparencyLogEntry,
  'logId' | 'inclusionPromise' | 'kindVersion'
>;

export function isVerifiableTransparencyLogEntry(
  entry: TransparencyLogEntry
): entry is VerifiableTransparencyLogEntry {
  return (
    entry.logId !== undefined &&
    entry.inclusionPromise !== undefined &&
    entry.kindVersion !== undefined
  );
}
