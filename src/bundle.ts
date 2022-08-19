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
import { Entry } from './client';
export const ATTESTATION_TYPE_BLOB = 'attestation/blob';
export const ATTESTATION_TYPE_DSSE = 'attestation/dsse';

interface DSSESignature {
  keyid: string;
  sig: string;
}

export interface DSSE {
  payloadType: string;
  payload: string;
  signatures: DSSESignature[];
}

interface AbstractSigstoreBundle {
  attestationType: string;
  attestation: object;
  certificate: string;
  signedEntryTimestamp: string;
  integratedTime: number;
  logIndex: number;
  logID: string;
}

export interface SigstoreBlobBundle extends AbstractSigstoreBundle {
  attestationType: typeof ATTESTATION_TYPE_BLOB;
  attestation: {
    payloadHash: string;
    payloadHashAlgorithm: string;
    signature: string;
  };
}

export interface SigstoreDSSEBundle extends AbstractSigstoreBundle {
  attestationType: typeof ATTESTATION_TYPE_DSSE;
  attestation: DSSE;
}

export type SigstoreBundle = SigstoreBlobBundle | SigstoreDSSEBundle;

export const buildBlobBundle = (
  digest: string,
  signature: string,
  certificate: string,
  rekorEntry: Entry
): SigstoreBlobBundle => ({
  attestationType: ATTESTATION_TYPE_BLOB,
  attestation: {
    payloadHash: digest,
    payloadHashAlgorithm: 'sha256',
    signature: signature,
  },
  certificate: certificate,
  signedEntryTimestamp: rekorEntry.verification.signedEntryTimestamp,
  integratedTime: rekorEntry.integratedTime,
  logID: rekorEntry.logID,
  logIndex: rekorEntry.logIndex,
});

export const buildDSSEBundle = (
  envelope: DSSE,
  certificate: string,
  rekorEntry: Entry
): SigstoreDSSEBundle => ({
  attestationType: ATTESTATION_TYPE_DSSE,
  attestation: envelope,
  certificate: certificate,
  signedEntryTimestamp: rekorEntry.verification.signedEntryTimestamp,
  integratedTime: rekorEntry.integratedTime,
  logID: rekorEntry.logID,
  logIndex: rekorEntry.logIndex,
});
