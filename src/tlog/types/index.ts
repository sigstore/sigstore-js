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
import { HashedRekorV001Schema } from './__generated__/hashedrekord';
import { IntotoV001Schema, IntotoV002Schema } from './__generated__/intoto';

export const INTOTO_KIND = 'intoto';
export const HASHEDREKORD_KIND = 'hashedrekord';

export type HashedRekordKind = {
  apiVersion: '0.0.1';
  kind: typeof HASHEDREKORD_KIND;
  spec: HashedRekorV001Schema;
};

export type IntotoKind =
  | {
      apiVersion: '0.0.1';
      kind: typeof INTOTO_KIND;
      spec: IntotoV001Schema;
    }
  | {
      apiVersion: '0.0.2';
      kind: typeof INTOTO_KIND;
      spec: IntotoV002Schema;
    };

export type EntryKind = HashedRekordKind | IntotoKind;

export interface Entry {
  uuid: string;
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  verification: EntryVerification;
  attestation?: object;
}

export interface EntryVerification {
  inclusionProof: InclusionProof;
  signedEntryTimestamp: string;
}

export interface InclusionProof {
  hashes: string[];
  logIndex: number;
  rootHash: string;
  treeSize: number;
}

export interface VerificationPayload {
  body: string;
  integratedTime: number;
  logIndex: number;
  logID: string;
}
