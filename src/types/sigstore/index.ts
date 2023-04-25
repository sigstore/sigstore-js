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
import {
  ArtifactVerificationOptions,
  Bundle,
  Envelope,
  HashAlgorithm,
  TransparencyLogEntry,
  VerificationMaterial,
} from '@sigstore/protobuf-specs';
import { encoding as enc, pem } from '../../util';
import { x509Certificate } from '../../x509/cert';
import { WithRequired } from '../utility';
import { ValidBundle, assertValidBundle } from './validate';

import type { Entry, EntryKind } from '../../tlog';
import type { SignatureMaterial } from '../signature';

export * from '@sigstore/protobuf-specs';
export * from './serialized';
export * from './validate';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const bundleFromJSON = (obj: any): ValidBundle => {
  const bundle = Bundle.fromJSON(obj);
  assertValidBundle(bundle);
  return bundle;
};

const BUNDLE_MEDIA_TYPE =
  'application/vnd.dev.sigstore.bundle+json;version=0.1';

// Subset of sigstore.Bundle that has verification material as part
// of the bundle
export type BundleWithVerificationMaterial = WithRequired<
  Bundle,
  'verificationMaterial'
>;

// Type guard for narrowing a Bundle to a BundleWithVerificationMaterial
export function isBundleWithVerificationMaterial(
  bundle: Bundle
): bundle is BundleWithVerificationMaterial {
  return bundle.verificationMaterial !== undefined;
}

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
    isBundleWithVerificationMaterial(bundle) &&
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

export function toDSSEBundle({
  envelope,
  signature,
  tlogEntry,
}: {
  envelope: Envelope;
  signature: SignatureMaterial;
  tlogEntry?: Entry;
}): Bundle {
  return {
    mediaType: BUNDLE_MEDIA_TYPE,
    content: { $case: 'dsseEnvelope', dsseEnvelope: envelope },
    verificationMaterial: toVerificationMaterial({ signature, tlogEntry }),
  };
}

export function toMessageSignatureBundle({
  digest,
  signature,
  tlogEntry,
}: {
  digest: Buffer;
  signature: SignatureMaterial;
  tlogEntry?: Entry;
}): Bundle {
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
    verificationMaterial: toVerificationMaterial({ signature, tlogEntry }),
  };
}

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
    canonicalizedBody: Buffer.from(entry.body, 'base64'),
  };
}

function toVerificationMaterial({
  signature,
  tlogEntry,
}: {
  signature: SignatureMaterial;
  tlogEntry?: Entry;
}): VerificationMaterial {
  return {
    content: signature.certificates
      ? toVerificationMaterialx509CertificateChain(signature.certificates)
      : toVerificationMaterialPublicKey(signature.key.id || ''),
    tlogEntries: tlogEntry ? [toTransparencyLogEntry(tlogEntry)] : [],
    timestampVerificationData: undefined,
  };
}

function toVerificationMaterialx509CertificateChain(
  certificates: string[]
): VerificationMaterial['content'] {
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
): VerificationMaterial['content'] {
  return { $case: 'publicKey', publicKey: { hint } };
}

export function signingCertificate(
  bundle: Bundle
): x509Certificate | undefined {
  if (!isBundleWithCertificateChain(bundle)) {
    return undefined;
  }

  const signingCert =
    bundle.verificationMaterial.content.x509CertificateChain.certificates[0];
  return x509Certificate.parse(signingCert.rawBytes);
}
