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
import { Rekor } from '../client';
import { bundle, Bundle, Envelope } from '../types/bundle';
import { SignatureMaterial } from '../types/signature';
import { toProposedHashedRekordEntry, toProposedIntotoEntry } from './format';

export { Entry, EntryKind, HashedRekordKind } from './types';

export interface TLog {
  createMessageSignatureEntry: (
    digest: Buffer,
    sigMaterial: SignatureMaterial
  ) => Promise<Bundle>;

  createDSSEEntry: (
    envelope: Envelope,
    sigMaterial: SignatureMaterial
  ) => Promise<Bundle>;
}

export interface TLogClientOptions {
  rekorBaseURL: string;
}

export class TLogClient implements TLog {
  private rekor: Rekor;

  constructor(options: TLogClientOptions) {
    this.rekor = new Rekor({ baseURL: options.rekorBaseURL });
  }

  async createMessageSignatureEntry(
    digest: Buffer,
    sigMaterial: SignatureMaterial
  ): Promise<Bundle> {
    const proposedEntry = toProposedHashedRekordEntry(digest, sigMaterial);

    const entry = await this.rekor.createEntry(proposedEntry);
    return bundle.toMessageSignatureBundle(digest, sigMaterial, entry);
  }

  async createDSSEEntry(
    envelope: Envelope,
    sigMaterial: SignatureMaterial
  ): Promise<Bundle> {
    const proposedEntry = toProposedIntotoEntry(envelope, sigMaterial);
    const entry = await this.rekor.createEntry(proposedEntry);
    return bundle.toDSSEBundle(envelope, sigMaterial, entry);
  }
}
