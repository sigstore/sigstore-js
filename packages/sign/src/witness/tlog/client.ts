/*
Copyright 2025 The Sigstore Authors.

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
import { internalError } from '../../error';
import { HTTPError } from '../../external/error';
import { Rekor } from '../../external/rekor';
import { RekorV2 } from '../../external/rekor-v2';

import type { TransparencyLogEntry } from '@sigstore/bundle';
import type { TransparencyLogEntry as TLE } from '@sigstore/protobuf-specs';
import type { CreateEntryRequest } from '@sigstore/protobuf-specs/rekor/v2';
import type { Entry, ProposedEntry } from '../../external/rekor';
import type { FetchOptions } from '../../types/fetch';

export type { Entry, ProposedEntry };

export interface TLog {
  createEntry: (proposedEntry: ProposedEntry) => Promise<Entry>;
}

export type TLogClientOptions = {
  rekorBaseURL: string;
  fetchOnConflict?: boolean;
} & FetchOptions;

export class TLogClient implements TLog {
  private rekor: Rekor;
  private fetchOnConflict: boolean;

  constructor(options: TLogClientOptions) {
    this.fetchOnConflict = options.fetchOnConflict ?? false;
    this.rekor = new Rekor({
      baseURL: options.rekorBaseURL,
      retry: options.retry,
      timeout: options.timeout,
    });
  }

  public async createEntry(proposedEntry: ProposedEntry): Promise<Entry> {
    let entry: Entry;

    try {
      entry = await this.rekor.createEntry(proposedEntry);
    } catch (err) {
      // If the entry already exists, fetch it (if enabled)
      if (entryExistsError(err) && this.fetchOnConflict) {
        // Grab the UUID of the existing entry from the location header
        /* istanbul ignore next */
        const uuid = err.location.split('/').pop() || '';
        try {
          entry = await this.rekor.getEntry(uuid);
        } catch (err) {
          internalError(
            err,
            'TLOG_FETCH_ENTRY_ERROR',
            'error fetching tlog entry'
          );
        }
      } else {
        internalError(
          err,
          'TLOG_CREATE_ENTRY_ERROR',
          'error creating tlog entry'
        );
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

export interface TLogV2 {
  createEntry: (
    createEntryRequest: CreateEntryRequest
  ) => Promise<TransparencyLogEntry>;
}

export type TLogV2ClientOptions = {
  rekorBaseURL: string;
} & FetchOptions;

export class TLogV2Client implements TLogV2 {
  private rekor: RekorV2;

  constructor(options: TLogV2ClientOptions) {
    this.rekor = new RekorV2({
      baseURL: options.rekorBaseURL,
      retry: options.retry,
      timeout: options.timeout,
    });
  }

  public async createEntry(
    createEntryRequest: CreateEntryRequest
  ): Promise<TransparencyLogEntry> {
    let entry: TLE;

    try {
      entry = await this.rekor.createEntry(createEntryRequest);
    } catch (err) {
      internalError(
        err,
        'TLOG_CREATE_ENTRY_ERROR',
        'error creating tlog entry'
      );
    }

    if (entry.logId === undefined || entry.kindVersion === undefined) {
      internalError(
        new Error('invalid tlog entry'),
        'TLOG_CREATE_ENTRY_ERROR',
        'error creating tlog entry'
      );
    }

    return {
      ...entry,
      logId: entry.logId,
      kindVersion: entry.kindVersion,
    };
  }
}
