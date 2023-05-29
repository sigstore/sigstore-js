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
import fetch, { FetchInterface } from 'make-fetch-happen';
import { ua } from '../util';
import { checkStatus } from './error';

import type {
  LogEntry,
  ProposedEntry,
  ProposedDSSEEntry,
  ProposedHashedRekordEntry,
  ProposedIntotoEntry,
  SearchIndex,
  SearchLogQuery,
} from '@sigstore/rekor-types';
import type { FetchOptions } from '../types/fetch';

export type {
  ProposedEntry,
  SearchIndex,
  SearchLogQuery,
  ProposedDSSEEntry,
  ProposedHashedRekordEntry,
  ProposedIntotoEntry,
};

// The LogEntry type from @sigstore/rekor-types is a Record type
// mapping the entry's UUID to the entry's data. This is really
// inconvenient to work with, so we define a new type here that
// flattens the data -- the entry's UUID is now a property of the
// entry's data.
export type Entry = {
  uuid: string;
} & LogEntry['x'];

// Client options
export type RekorOptions = {
  baseURL: string;
} & FetchOptions;

/**
 * Rekor API client.
 */
export class Rekor {
  private fetch: FetchInterface;

  private baseUrl: string;
  constructor(options: RekorOptions) {
    this.fetch = fetch.defaults({
      retry: options.retry,
      timeout: options.timeout,
      headers: {
        Accept: 'application/json',
        'User-Agent': ua.getUserAgent(),
      },
    });

    this.baseUrl = options.baseURL;
  }

  /**
   * Create a new entry in the Rekor log.
   * @param propsedEntry {ProposedEntry} Data to create a new entry
   * @returns {Promise<Entry>} The created entry
   */
  public async createEntry(propsedEntry: ProposedEntry): Promise<Entry> {
    const url = `${this.baseUrl}/api/v1/log/entries`;

    const response = await this.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(propsedEntry),
    });
    checkStatus(response);

    const data = await response.json();
    return entryFromResponse(data);
  }

  /**
   * Get an entry from the Rekor log.
   * @param uuid {string} The UUID of the entry to retrieve
   * @returns {Promise<Entry>} The retrieved entry
   */
  public async getEntry(uuid: string): Promise<Entry> {
    const url = `${this.baseUrl}/api/v1/log/entries/${uuid}`;

    const response = await this.fetch(url);
    checkStatus(response);

    const data: LogEntry = await response.json();
    return entryFromResponse(data);
  }

  /**
   * Search the Rekor log index for entries matching the given query.
   * @param opts {SearchIndex} Options to search the Rekor log
   * @returns {Promise<string[]>} UUIDs of matching entries
   */
  public async searchIndex(opts: SearchIndex): Promise<string[]> {
    const url = `${this.baseUrl}/api/v1/index/retrieve`;

    const response = await this.fetch(url, {
      method: 'POST',
      body: JSON.stringify(opts),
      headers: { 'Content-Type': 'application/json' },
    });
    checkStatus(response);

    const data = await response.json();
    return data;
  }

  /**
   * Search the Rekor logs for matching the given query.
   * @param opts {SearchLogQuery} Query to search the Rekor log
   * @returns {Promise<Entry[]>} List of matching entries
   */
  public async searchLog(opts: SearchLogQuery): Promise<Entry[]> {
    const url = `${this.baseUrl}/api/v1/log/entries/retrieve`;

    const response = await this.fetch(url, {
      method: 'POST',
      body: JSON.stringify(opts),
      headers: { 'Content-Type': 'application/json' },
    });
    checkStatus(response);

    const rawData: LogEntry[] = await response.json();
    const data = rawData.map((d) => entryFromResponse(d));
    return data;
  }
}

// Unpack the response from the Rekor API into a more convenient format.
function entryFromResponse(data: LogEntry): Entry {
  const entries = Object.entries(data);

  if (entries.length != 1) {
    throw new Error('Received multiple entries in Rekor response');
  }

  // Grab UUID and entry data from the response
  const [uuid, entry] = entries[0];

  return {
    ...entry,
    uuid,
  };
}
