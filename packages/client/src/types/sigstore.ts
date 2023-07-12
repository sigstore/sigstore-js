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
import { BUNDLE_V01_MEDIA_TYPE } from '@sigstore/bundle';
import { HashAlgorithm } from '@sigstore/protobuf-specs';
import { encoding as enc, pem } from '../util';
import { SignatureMaterial } from './signature';

import type { Bundle, TransparencyLogEntry } from '@sigstore/bundle';
import type {
  ArtifactVerificationOptions,
  Envelope,
  InclusionProof,
  PublicKey,
  TimestampVerificationData,
  TransparencyLogInstance,
} from '@sigstore/protobuf-specs';
import type {
  Entry,
  ProposedEntry,
  RekorInclusionProof,
} from '../external/rekor';
import type { WithRequired } from './utility';

// Enums from protobuf-specs
// TODO: Move Envelope to "type" export once @sigstore/sign is a thing
export {
  Envelope,
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

// All of the following functions are used to construct a ValidBundle
// from various types of input. When this code moves into the
// @sigstore/sign package, these functions will be exported from there.
export function toDSSEBundle({
  envelope,
  signature,
  tlogEntry,
  timestamp,
}: {
  envelope: Envelope;
  signature: SignatureMaterial;
  tlogEntry?: Entry;
  timestamp?: Buffer;
}): Bundle {
  return {
    mediaType: BUNDLE_V01_MEDIA_TYPE,
    content: { $case: 'dsseEnvelope', dsseEnvelope: envelope },
    verificationMaterial: toVerificationMaterial({
      signature,
      tlogEntry,
      timestamp,
    }),
  };
}

export function toMessageSignatureBundle({
  digest,
  signature,
  tlogEntry,
  timestamp,
}: {
  digest: Buffer;
  signature: SignatureMaterial;
  tlogEntry?: Entry;
  timestamp?: Buffer;
}): Bundle {
  return {
    mediaType: BUNDLE_V01_MEDIA_TYPE,
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
    verificationMaterial: toVerificationMaterial({
      signature,
      tlogEntry,
      timestamp,
    }),
  };
}

function toTransparencyLogEntry(entry: Entry): TransparencyLogEntry {
  /* istanbul ignore next */
  const b64SET = entry.verification?.signedEntryTimestamp || '';
  const set = Buffer.from(b64SET, 'base64');
  const logID = Buffer.from(entry.logID, 'hex');
  const proof = entry.verification?.inclusionProof
    ? toInclusionProof(entry.verification.inclusionProof)
    : undefined;

  // Parse entry body so we can extract the kind and version.
  const bodyJSON = enc.base64Decode(entry.body);
  const entryBody: ProposedEntry = JSON.parse(bodyJSON);

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
    inclusionProof: proof,
    canonicalizedBody: Buffer.from(entry.body, 'base64'),
  };
}

function toInclusionProof(proof: RekorInclusionProof): InclusionProof {
  return {
    logIndex: proof.logIndex.toString(),
    rootHash: Buffer.from(proof.rootHash, 'hex'),
    treeSize: proof.treeSize.toString(),
    checkpoint: {
      envelope: proof.checkpoint,
    },
    hashes: proof.hashes.map((h) => Buffer.from(h, 'hex')),
  };
}

function toVerificationMaterial({
  signature,
  tlogEntry,
  timestamp,
}: {
  signature: SignatureMaterial;
  tlogEntry?: Entry;
  timestamp?: Buffer;
}): Bundle['verificationMaterial'] {
  return {
    content: signature.certificates
      ? toVerificationMaterialx509CertificateChain(signature.certificates)
      : toVerificationMaterialPublicKey(signature.key.id || ''),
    tlogEntries: tlogEntry ? [toTransparencyLogEntry(tlogEntry)] : [],
    timestampVerificationData: timestamp
      ? toTimestampVerificationData(timestamp)
      : undefined,
  };
}

function toVerificationMaterialx509CertificateChain(
  certificates: string[]
): Bundle['verificationMaterial']['content'] {
  return {
    $case: 'x509CertificateChain',
    x509CertificateChain: {
      certificates: certificates.map((c) => ({
        rawBytes: pem.toDER(c),
      })),
    },
  };
}

function toVerificationMaterialPublicKey(
  hint: string
): Bundle['verificationMaterial']['content'] {
  return { $case: 'publicKey', publicKey: { hint } };
}

function toTimestampVerificationData(
  timestamp: Buffer
): TimestampVerificationData {
  return {
    rfc3161Timestamps: [{ signedTimestamp: timestamp }],
  };
}
