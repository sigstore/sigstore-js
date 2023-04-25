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
import { InternalError } from '../error';
import { HTTPError, Rekor } from '../external';
import { SignatureMaterial } from '../types/signature';
import * as sigstore from '../types/sigstore';
import { toProposedHashedRekordEntry, toProposedIntotoEntry } from './format';
import { Entry, EntryKind } from './types';

interface CreateEntryOptions {
  fetchOnConflict?: boolean;
}

export { Entry, EntryKind, HashedRekordKind } from './types';

export interface TLog {
  createMessageSignatureEntry: (
    digest: Buffer,
    sigMaterial: SignatureMaterial
  ) => Promise<Entry>;

  createDSSEEntry: (
    envelope: sigstore.Envelope,
    sigMaterial: SignatureMaterial,
    options?: CreateEntryOptions
  ) => Promise<Entry>;
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
    sigMaterial: SignatureMaterial,
    options: CreateEntryOptions = {}
  ): Promise<Entry> {
    const proposedEntry = toProposedHashedRekordEntry(digest, sigMaterial);
    return this.createEntry(proposedEntry, options.fetchOnConflict);
  }

  async createDSSEEntry(
    envelope: sigstore.Envelope,
    sigMaterial: SignatureMaterial,
    options: CreateEntryOptions = {}
  ): Promise<Entry> {
    const proposedEntry = toProposedIntotoEntry(envelope, sigMaterial);
    return this.createEntry(proposedEntry, options.fetchOnConflict);
  }

  private async createEntry(
    proposedEntry: EntryKind,
    fetchOnConflict = false
  ): Promise<Entry> {
    let entry: Entry;

    try {
      entry = await this.rekor.createEntry(proposedEntry);
    } catch (err) {
      // If the entry already exists, fetch it (if enabled)
      if (entryExistsError(err) && fetchOnConflict) {
        // Grab the UUID of the existing entry from the location header
        const uuid = err.location.split('/').pop() || '';
        try {
          entry = await this.rekor.getEntry(uuid);
        } catch (err) {
          throw new InternalError({
            code: 'TLOG_FETCH_ENTRY_ERROR',
            message: 'error fetching tlog entry',
            cause: err,
          });
        }
      } else {
        throw new InternalError({
          code: 'TLOG_CREATE_ENTRY_ERROR',
          message: 'error creating tlog entry',
          cause: err,
        });
      }
    }

    return entry;
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
