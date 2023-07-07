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
import { Bundle as ProtoBundle } from '@sigstore/protobuf-specs';
import { assertBundle } from './validate';

import type { Bundle } from './bundle';
import type { OneOf } from './utility';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const bundleFromJSON = (obj: any): Bundle => {
  const bundle = ProtoBundle.fromJSON(obj);
  assertBundle(bundle);
  return bundle;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const bundleToJSON = (bundle: Bundle): SerializedBundle => {
  return ProtoBundle.toJSON(bundle) as SerializedBundle;
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
  inclusionPromise: {
    signedEntryTimestamp: string;
  };
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
type SerializedDSSEEnvelope = {
  payload: string;
  payloadType: string;
  signatures: {
    sig: string;
    keyid: string;
  }[];
};

// Serialized form of the DSSE Envelope
export type { SerializedDSSEEnvelope as SerializedEnvelope };

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
  dsseEnvelope: SerializedDSSEEnvelope;
  messageSignature: SerializedMessageSignature;
}>;
