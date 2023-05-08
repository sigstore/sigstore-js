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
import { VerificationError } from '../../error';
import * as sigstore from '../../types/sigstore';
import { x509Certificate } from '../../x509/cert';
import { verifyTLogBody } from './body';
import { verifyTLogSET } from './set';

// Verifies that the number of tlog entries that pass offline verification
// is greater than or equal to the threshold specified in the options.
export function verifyTLogEntries(
  bundle: sigstore.BundleWithVerificationMaterial,
  trustedRoot: sigstore.TrustedRoot,
  options: sigstore.ArtifactVerificationOptions_TlogOptions
): void {
  if (options.performOnlineVerification) {
    throw new VerificationError('Online verification not implemented');
  }

  // Extract the signing cert, if available
  const signingCert = sigstore.signingCertificate(bundle);

  // Iterate over the tlog entries and verify each one
  const verifiedEntries = bundle.verificationMaterial.tlogEntries.filter(
    (entry) =>
      verifyTLogEntryOffline(
        entry,
        bundle.content,
        trustedRoot.tlogs,
        signingCert
      )
  );

  if (verifiedEntries.length < options.threshold) {
    throw new VerificationError('tlog verification failed');
  }
}

function verifyTLogEntryOffline(
  entry: sigstore.TransparencyLogEntry,
  bundleContent: sigstore.Bundle['content'],
  tlogs: sigstore.TransparencyLogInstance[],
  signingCert?: x509Certificate
): boolean {
  // Check that the TLog entry has the fields necessary for verification
  if (!sigstore.isVerifiableTransparencyLogEntry(entry)) {
    return false;
  }

  // If there is a signing certificate availble, check that the tlog integrated
  // time is within the certificate's validity period; otherwise, skip this
  // check.
  const verifyTLogIntegrationTime = signingCert
    ? () =>
        signingCert.validForDate(new Date(Number(entry.integratedTime) * 1000))
    : () => true;

  return (
    verifyTLogBody(entry, bundleContent) &&
    verifyTLogSET(entry, tlogs) &&
    verifyTLogIntegrationTime()
  );
}
