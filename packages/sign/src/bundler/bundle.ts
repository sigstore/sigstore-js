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
import * as sigstore from '@sigstore/bundle';
import { crypto, pem } from '../util';

import type { Signature } from '../signer';
import type { Artifact } from './base';

// Helper functions for assembling the parts of a Sigstore bundle

// Message signature bundle - $case: 'messageSignature'
export function toMessageSignatureBundle(
  artifact: Artifact,
  signature: Signature
): sigstore.BundleWithMessageSignature {
  const digest = crypto.digest('sha256', artifact.data);

  return sigstore.toMessageSignatureBundle({
    digest,
    signature: signature.signature,
    certificate:
      signature.key.$case === 'x509Certificate'
        ? pem.toDER(signature.key.certificate)
        : undefined,
    keyHint:
      signature.key.$case === 'publicKey' ? signature.key.hint : undefined,
    certificateChain: true,
  });
}

// DSSE envelope bundle - $case: 'dsseEnvelope'
export function toDSSEBundle(
  artifact: Required<Artifact>,
  signature: Signature,
  certificateChain?: boolean
): sigstore.BundleWithDsseEnvelope {
  return sigstore.toDSSEBundle({
    artifact: artifact.data,
    artifactType: artifact.type,
    signature: signature.signature,
    certificate:
      signature.key.$case === 'x509Certificate'
        ? pem.toDER(signature.key.certificate)
        : undefined,
    keyHint:
      signature.key.$case === 'publicKey' ? signature.key.hint : undefined,
    certificateChain,
  });
}
