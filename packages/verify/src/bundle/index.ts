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
import { Bundle } from '@sigstore/bundle';
import { RFC3161Timestamp, X509Certificate } from '@sigstore/core';
import { DSSESignatureContent } from './dsse';
import { MessageSignatureContent } from './message';

import type {
  SignatureContent,
  SignedEntity,
  Timestamp,
  VerificationKey,
} from '../shared.types';

export function toSignedEntity(
  bundle: Bundle,
  artifact?: Buffer
): SignedEntity {
  const { tlogEntries, timestampVerificationData } =
    bundle.verificationMaterial;
  const timestamps: Timestamp[] = [];

  for (const entry of tlogEntries) {
    if (entry.integratedTime && entry.integratedTime !== '0') {
      timestamps.push({
        $case: 'transparency-log',
        tlogEntry: entry,
      });
    }
  }

  for (const ts of timestampVerificationData?.rfc3161Timestamps ?? []) {
    timestamps.push({
      $case: 'timestamp-authority',
      timestamp: RFC3161Timestamp.parse(Buffer.from(ts.signedTimestamp)),
    });
  }

  return {
    signature: signatureContent(bundle, artifact),
    key: key(bundle),
    tlogEntries,
    timestamps,
  };
}

export function signatureContent(
  bundle: Bundle,
  artifact?: Buffer
): SignatureContent {
  switch (bundle.content.$case) {
    case 'dsseEnvelope':
      return new DSSESignatureContent(bundle.content.dsseEnvelope);
    case 'messageSignature':
      return new MessageSignatureContent(
        bundle.content.messageSignature,
        artifact!
      );
  }
}

function key(bundle: Bundle): VerificationKey {
  switch (bundle.verificationMaterial.content.$case) {
    case 'publicKey':
      return {
        $case: 'public-key',
        hint: bundle.verificationMaterial.content.publicKey.hint,
      };
    case 'x509CertificateChain':
      return {
        $case: 'certificate',
        certificate: X509Certificate.parse(
          Buffer.from(
            bundle.verificationMaterial.content.x509CertificateChain
              .certificates[0].rawBytes
          )
        ),
      };
    case 'certificate':
      return {
        $case: 'certificate',
        certificate: X509Certificate.parse(
          Buffer.from(bundle.verificationMaterial.content.certificate.rawBytes)
        ),
      };
  }
}
