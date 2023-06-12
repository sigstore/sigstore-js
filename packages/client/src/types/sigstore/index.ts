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
import { Bundle, HashAlgorithm } from '@sigstore/protobuf-specs';
import { encoding as enc, pem } from '../../util';
import { SignatureMaterial } from '../signature';
import { ValidBundle, assertValidBundle } from './validate';

import type {
  ArtifactVerificationOptions,
  Envelope,
  TimestampVerificationData,
  TransparencyLogEntry,
  VerificationMaterial,
} from '@sigstore/protobuf-specs';
import type { Entry, ProposedEntry } from '../../external/rekor';
import type { WithRequired } from '../utility';
import type { SerializedBundle } from './serialized';

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

const BUNDLE_MEDIA_TYPE =
  'application/vnd.dev.sigstore.bundle+json;version=0.1';

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
}): ValidBundle {
  return {
    mediaType: BUNDLE_MEDIA_TYPE,
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
}): ValidBundle {
  return {
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
    verificationMaterial: toVerificationMaterial({
      signature,
      tlogEntry,
      timestamp,
    }),
  };
}

function toTransparencyLogEntry(entry: Entry): TransparencyLogEntry {
  const b64SET = entry.verification?.signedEntryTimestamp || '';
  const set = Buffer.from(b64SET, 'base64');
  const logID = Buffer.from(entry.logID, 'hex');

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
    inclusionProof: undefined,
    canonicalizedBody: Buffer.from(entry.body, 'base64'),
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
}): ValidBundle['verificationMaterial'] {
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
): ValidBundle['verificationMaterial']['content'] {
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
): ValidBundle['verificationMaterial']['content'] {
  return { $case: 'publicKey', publicKey: { hint } };
}

function toTimestampVerificationData(
  timestamp: Buffer
): TimestampVerificationData {
  return {
    rfc3161Timestamps: [{ signedTimestamp: timestamp }],
  };
}
