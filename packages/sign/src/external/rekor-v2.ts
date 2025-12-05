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
import { fetchWithRetry } from './fetch';

import type { TransparencyLogEntry } from '@sigstore/protobuf-specs';
import { CreateEntryRequest } from '@sigstore/protobuf-specs/rekor/v2';
import type { FetchOptions } from '../types/fetch';

// Client options
export type RekorOptions = {
  baseURL: string;
} & FetchOptions;

/**
 * Rekor API client.
 */
export class RekorV2 {
  private options: RekorOptions;

  constructor(options: RekorOptions) {
    this.options = options;
  }

  public async createEntry(
    proposedEntry: CreateEntryRequest
  ): Promise<TransparencyLogEntry> {
    const { baseURL, timeout, retry } = this.options;
    const url = `${baseURL}/api/v2/log/entries`;
    const response = await fetchWithRetry(url, {
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(CreateEntryRequest.toJSON(proposedEntry)),
      timeout,
      retry,
    });

    return response.json();
  }
}
