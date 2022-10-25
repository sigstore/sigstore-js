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
import { encoding as enc, pem } from '../../util';
import { Entry, EntryKind } from '../rekor';
import { SignatureMaterial } from '../signature';
import { Envelope } from './__generated__/envelope';
import { Bundle } from './__generated__/sigstore_bundle';
import {
  HashAlgorithm,
  VerificationMaterial,
} from './__generated__/sigstore_common';
import { TransparencyLogEntry } from './__generated__/sigstore_rekor';

export * from './serialized';
export * from './__generated__/envelope';
export * from './__generated__/sigstore_bundle';
export * from './__generated__/sigstore_common';

const BUNDLE_MEDIA_TYPE =
  'application/vnd.dev.sigstore.bundle+json;version=0.1';

export const bundle = {
  toDSSEBundle: (
    envelope: Envelope,
    signature: SignatureMaterial,
    rekorEntry: Entry
  ): Bundle => ({
    mediaType: BUNDLE_MEDIA_TYPE,
    content: {
      $case: 'dsseEnvelope',
      dsseEnvelope: envelope,
    },
    verificationData: {
      tlogEntries: [toTransparencyLogEntry(rekorEntry)],
      timestampVerificationData: {
        rfc3161Timestamps: [],
      },
    },
    verificationMaterial: toVerificationMaterial(signature),
  }),

  toMessageSignatureBundle: (
    digest: Buffer,
    signature: SignatureMaterial,
    rekorEntry: Entry
  ): Bundle => ({
    mediaType: BUNDLE_MEDIA_TYPE,
    content: {
      $case: 'messageSignature',
      messageSignature: {
        messageDigest: {
          algorithm: HashAlgorithm.SHA2_256,
          digest: digest,
        },
        signature: signature.signature,
      },
    },
    verificationData: {
      tlogEntries: [toTransparencyLogEntry(rekorEntry)],
      timestampVerificationData: {
        rfc3161Timestamps: [],
      },
    },
    verificationMaterial: toVerificationMaterial(signature),
  }),
};

function toTransparencyLogEntry(entry: Entry): TransparencyLogEntry {
  const set = Buffer.from(entry.verification.signedEntryTimestamp, 'base64');
  const logID = Buffer.from(entry.logID, 'hex');

  // Parse entry body so we can extract the kind and version.
  const bodyJSON = enc.base64Decode(entry.body);
  const entryBody: EntryKind = JSON.parse(bodyJSON);

  return {
    inclusionPromise: {
      signedEntryTimestamp: set,
    },
    logIndex: entry.logIndex.toString(),
    logId: {
      keyId: logID,
    },
    integratedTime: entry.integratedTime.toString(),
    kindVersion: {
      kind: entryBody.kind,
      version: entryBody.apiVersion,
    },
    inclusionProof: undefined,
  };
}

function toVerificationMaterial(
  signature: SignatureMaterial
): VerificationMaterial {
  return signature.certificates
    ? toVerificationMaterialx509CertificateChain(signature.certificates)
    : toVerificationMaterialPublicKey(signature.key.id || '');
}

function toVerificationMaterialx509CertificateChain(
  certificates: string[]
): VerificationMaterial {
  return {
    content: {
      $case: 'x509CertificateChain',
      x509CertificateChain: {
        certificates: certificates.map((c) => ({
          derBytes: pem.toDER(c),
        })),
      },
    },
  };
}

function toVerificationMaterialPublicKey(hint: string): VerificationMaterial {
  return {
    content: {
      $case: 'publicKey',
      publicKey: { hint },
    },
  };
}
