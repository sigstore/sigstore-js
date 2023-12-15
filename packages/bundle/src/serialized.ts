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
import { Envelope, Bundle as ProtoBundle } from '@sigstore/protobuf-specs';
import { BUNDLE_V01_MEDIA_TYPE, Bundle } from './bundle';
import { assertBundle, assertBundleLatest, assertBundleV01 } from './validate';

import type { OneOf } from './utility';

export const bundleFromJSON = (obj: unknown): Bundle => {
  const bundle = ProtoBundle.fromJSON(obj);
  assertBundle(bundle);

  if (bundle.mediaType === BUNDLE_V01_MEDIA_TYPE) {
    assertBundleV01(bundle);
  } else {
    assertBundleLatest(bundle);
  }

  return bundle;
};

export const bundleToJSON = (bundle: Bundle): SerializedBundle => {
  return ProtoBundle.toJSON(bundle) as SerializedBundle;
};

export const envelopeFromJSON = (obj: unknown): Envelope => {
  return Envelope.fromJSON(obj);
};

export const envelopeToJSON = (envelope: Envelope): SerializedEnvelope => {
  return Envelope.toJSON(envelope) as SerializedEnvelope;
};

type SerializedTLogEntry = {
  logIndex: string;
  logId: {
    keyId: string;
  };
  kindVersion:
    | {
        kind: string;
        version: string;
      }
    | undefined;
  integratedTime: string;
  inclusionPromise:
    | {
        signedEntryTimestamp: string;
      }
    | undefined;
  inclusionProof:
    | {
        logIndex: string;
        rootHash: string;
        treeSize: string;
        hashes: string[];
        checkpoint: { envelope: string };
      }
    | undefined;
  canonicalizedBody: string;
};

type SerializedTimestampVerificationData = {
  rfc3161Timestamps: { signedTimestamp: string }[];
};

// Serialized form of the messageSignature option in the Sigstore Bundle
type SerializedMessageSignature = {
  messageDigest:
    | {
        algorithm: string;
        digest: string;
      }
    | undefined;
  signature: string;
};

// Serialized form of the dsseEnvelope option in the Sigstore Bundle
export type SerializedEnvelope = {
  payload: string;
  payloadType: string;
  signatures: {
    sig: string;
    keyid: string;
  }[];
};

// Serialized form of the Sigstore Bundle union type with all possible options
// represented
export type SerializedBundle = {
  mediaType: string;
  verificationMaterial: (
    | OneOf<{
        x509CertificateChain: { certificates: { rawBytes: string }[] };
        publicKey: { hint: string };
      }>
    | undefined
  ) & {
    tlogEntries: SerializedTLogEntry[];
    timestampVerificationData: SerializedTimestampVerificationData | undefined;
  };
} & OneOf<{
  dsseEnvelope: SerializedEnvelope;
  messageSignature: SerializedMessageSignature;
}>;
