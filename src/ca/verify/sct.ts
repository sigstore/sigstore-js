/*
Copyright 2022 The Sigstore Authors.

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

export function verifySCTs(
  certificateChain: x509Certificate[],
  ctLogs: sigstore.TransparencyLogInstance[],
  options: sigstore.ArtifactVerificationOptions_CtlogOptions
) {
  const signingCert = certificateChain[0];
  const issuerCert = certificateChain[1];
  const sctResults = signingCert.verifySCTs(issuerCert, ctLogs);

  // Count the number of verified SCTs which were found
  const verifiedSCTCount = sctResults.filter((sct) => sct.verified).length;

  if (verifiedSCTCount < options.threshold) {
    throw new VerificationError(
      `Not enough SCTs verified (found ${verifiedSCTCount}, need ${options.threshold})`
    );
  }
}
