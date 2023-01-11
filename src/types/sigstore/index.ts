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
import { Bundle, VerificationMaterial } from './__generated__/sigstore_bundle';
import { ArtifactVerificationOptions } from './__generated__/sigstore_verification';

export * from './__generated__/sigstore_bundle';
export * from './__generated__/sigstore_common';
export * from './__generated__/sigstore_trustroot';
export * from './__generated__/sigstore_verification';

// Subset of sigstore.Bundle that has a certificate chain as part
// of the verification material (as opposed to a public key)
export type BundleWithCertificateChain = Bundle & {
  verificationMaterial: VerificationMaterial & {
    content: Extract<
      VerificationMaterial['content'],
      { $case: 'x509CertificateChain' }
    >;
  };
};

// Type guard for narrowing a Bundle to a BundleWithCertificateChain
export function isBundleWithCertificateChain(
  bundle: Bundle
): bundle is BundleWithCertificateChain {
  return (
    bundle.verificationMaterial !== undefined &&
    bundle.verificationMaterial.content !== undefined &&
    bundle.verificationMaterial.content.$case === 'x509CertificateChain'
  );
}

// Subset of sigstore.ArtifactVerificationOptions that has a
// both ctlogOptions and certificate identities defined
export type CAArtifactVerificationOptions = Required<
  Pick<ArtifactVerificationOptions, 'ctlogOptions'>
> & {
  signers: Extract<
    ArtifactVerificationOptions['signers'],
    { $case: 'certificateIdentities' }
  >;
};

export function isCAVerificationOptions(
  options: ArtifactVerificationOptions
): options is CAArtifactVerificationOptions {
  return (
    options.ctlogOptions !== undefined &&
    options.signers !== undefined &&
    options.signers.$case === 'certificateIdentities'
  );
}
