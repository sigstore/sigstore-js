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
import { X509Certificate, crypto } from '@sigstore/core';
import { VerificationError } from '../error';
import { verifyCertificateChain } from './certificate';
import { VerifiedSCTProvider, verifySCTs } from './sct';

import type { CertificateIdentity, Signer } from '../shared.types';
import type { TrustMaterial } from '../trust';

const OID_FULCIO_ISSUER_V1 = '1.3.6.1.4.1.57264.1.1';
const OID_FULCIO_ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';

export type CertificateVerificationResult = {
  signer: Signer;
  scts: VerifiedSCTProvider[];
};

export function verifyPublicKey(
  hint: string,
  timestamps: Date[],
  trustMaterial: TrustMaterial
): Signer {
  const key = trustMaterial.publicKey(hint);

  timestamps.forEach((timestamp) => {
    if (!key.validFor(timestamp)) {
      throw new VerificationError({
        code: 'PUBLIC_KEY_ERROR',
        message: `Public key is not valid for timestamp: ${timestamp.toISOString()}`,
      });
    }
  });

  return { key: key.publicKey };
}

export function verifyCertificate(
  leaf: X509Certificate,
  timestamps: Date[],
  trustMaterial: TrustMaterial
): CertificateVerificationResult {
  // Check that leaf certificate chains to a trusted CA
  const path = verifyCertificateChain(
    leaf,
    trustMaterial.certificateAuthorities
  );

  // Check that ALL certificates are valid for ALL of the timestamps
  const validForDate = timestamps.every((timestamp) =>
    path.every((cert) => cert.validForDate(timestamp))
  );

  if (!validForDate) {
    throw new VerificationError({
      code: 'CERTIFICATE_ERROR',
      message: 'certificate is not valid or expired at the specified date',
    });
  }

  return {
    scts: verifySCTs(path[0], path[1], trustMaterial.ctlogs),
    signer: getSigner(path[0]),
  };
}

function getSigner(cert: X509Certificate): Signer {
  let issuer: string | undefined;
  const issuerExtension = cert.extension(OID_FULCIO_ISSUER_V2);

  if (issuerExtension) {
    issuer = issuerExtension.valueObj.subs?.[0]?.value.toString('ascii');
  } else {
    issuer = cert.extension(OID_FULCIO_ISSUER_V1)?.value.toString('ascii');
  }

  const identity: CertificateIdentity = {
    extensions: { issuer },
    subjectAlternativeName: cert.subjectAltName,
  };

  return {
    key: crypto.createPublicKey(cert.publicKey),
    identity,
  };
}
