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
import { HTTPError } from '../client/error';
import { InternalError } from '../error';
import { SignatureMaterial } from '../types/signature';
import { bundle, Bundle, Envelope } from '../types/sigstore';
import { toProposedHashedRekordEntry, toProposedIntotoEntry } from './format';
import { Entry } from './types';

interface CreateEntryOptions {
  fetchOnConflict?: boolean;
}

export { Entry, EntryKind, HashedRekordKind } from './types';

export interface TLog {
  createMessageSignatureEntry: (
    digest: Buffer,
    sigMaterial: SignatureMaterial
  ) => Promise<Bundle>;

  createDSSEEntry: (
    envelope: Envelope,
    sigMaterial: SignatureMaterial,
    options?: CreateEntryOptions
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

    try {
      const entry = await this.rekor.createEntry(proposedEntry);
      return bundle.toMessageSignatureBundle(digest, sigMaterial, entry);
    } catch (err) {
      throw new InternalError('error creating tlog entry', err);
    }
  }

  async createDSSEEntry(
    envelope: Envelope,
    sigMaterial: SignatureMaterial,
    options: CreateEntryOptions = {}
  ): Promise<Bundle> {
    const fetchOnConflict = options.fetchOnConflict ?? false;
    let entry: Entry;

    try {
      const proposedEntry = toProposedIntotoEntry(envelope, sigMaterial);
      entry = await this.rekor.createEntry(proposedEntry);
    } catch (err) {
      // If the entry already exists, fetch it (if enabled)
      if (entryExistsError(err) && fetchOnConflict) {
        // Grab the UUID of the existing entry from the location header
        const uuid = err.location.split('/').pop() || '';
        entry = await this.rekor.getEntry(uuid);
      } else {
        throw new InternalError('error creating tlog entry', err);
      }
    }

    return bundle.toDSSEBundle(envelope, sigMaterial, entry);
  }
}

function entryExistsError(
  value: unknown
): value is HTTPError & { location: string } {
  return (
    value instanceof HTTPError &&
    value.statusCode === 409 &&
    value.location !== undefined
  );
}
