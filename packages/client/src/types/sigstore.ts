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
  ArtifactVerificationOptions,
  PublicKey,
  TransparencyLogInstance,
} from '@sigstore/protobuf-specs';
import type { WithRequired } from './utility';

// Enums from protobuf-specs
export { SubjectAlternativeNameType } from '@sigstore/protobuf-specs';

// Types from protobuf-specs
export type {
  ArtifactVerificationOptions,
  ArtifactVerificationOptions_CtlogOptions,
  ArtifactVerificationOptions_TlogOptions,
  CertificateAuthority,
  CertificateIdentities,
  CertificateIdentity,
  Envelope,
  ObjectIdentifierValuePair,
  PublicKey,
  SubjectAlternativeName,
  TransparencyLogInstance,
  TrustedRoot,
} from '@sigstore/protobuf-specs';

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

export type ViableTransparencyLogInstance = TransparencyLogInstance & {
  logId: NonNullable<TransparencyLogInstance['logId']>;
  publicKey: WithRequired<PublicKey, 'rawBytes'>;
};
