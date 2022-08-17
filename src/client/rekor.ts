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
import { checkStatus } from './error';
import { getUserAgent } from '../util';

const DEFAULT_BASE_URL = 'https://rekor.sigstore.dev';
const ENTRY_KIND = 'hashedrekord';
const API_VERSION = '0.0.1';

// Client options
export interface RekorOptions {
  baseURL?: string;
}

export interface ProposedEntry {
  artifactSignature: string;
  artifactDigest: string;
  certificate: string;
}

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

export interface SearchIndex {
  email?: string;
  hash?: string;
}

/**
 * Rekor API client.
 */
export class Rekor {
  private fetch: FetchInterface;

  private baseUrl: string;
  constructor(options: RekorOptions) {
    this.fetch = fetch.defaults({
      retry: { retries: 2 },
      timeout: 5000,
      headers: {
        Accept: 'application/json',
        'User-Agent': getUserAgent(),
      },
    });
    this.baseUrl = options.baseURL ?? DEFAULT_BASE_URL;
  }

  /**
   * Create a new entry in the Rekor log.
   * @param propsedEntry {ProposedEntry} Data to create a new entry
   * @returns {Promise<Entry>} The created entry
   */
  public async createEntry(propsedEntry: ProposedEntry): Promise<Entry> {
    const url = `${this.baseUrl}/api/v1/log/entries`;

    const body = {
      kind: ENTRY_KIND,
      apiVersion: API_VERSION,
      spec: {
        data: {
          hash: { algorithm: 'sha256', value: propsedEntry.artifactDigest },
        },
        signature: {
          format: 'x509',
          content: propsedEntry.artifactSignature,
          publicKey: { content: propsedEntry.certificate },
        },
      },
    };

    const response = await this.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
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

    const data = await response.json();
    return entryFromResponse(data);
  }

  /**
   * Search the Rekor log for entries matching the given query.
   * @param opts {SearchIndex} Options to search the Rekor log
   * @returns {Promise<string[]>} UUIDs of matching entries
   */
  public async searchLog(opts: SearchIndex): Promise<string[]> {
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
}

// Unpack the response from the Rekor API into a more convenient format.
function entryFromResponse(data: object): Entry {
  const entries = Object.entries(data);

  if (entries.length != 1) {
    throw new Error('Received multiple entries in Rekor response');
  }

  // Grab UUID and entry data from the response
  const [uuid, entry] = Object.entries(data)[0];

  return {
    ...(entry as Entry),
    uuid,
  };
}
