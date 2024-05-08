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
import { fetchWithRetry } from './fetch';

import type { FetchOptions } from '../types/fetch';

export interface TimestampRequest {
  artifactHash: string;
  hashAlgorithm: string;
  certificates?: boolean;
  nonce?: number;
  tsaPolicyOID?: string;
}

export type TimestampAuthorityOptions = {
  baseURL: string;
} & FetchOptions;

export class TimestampAuthority {
  private options: TimestampAuthorityOptions;

  constructor(options: TimestampAuthorityOptions) {
    this.options = options;
  }

  public async createTimestamp(request: TimestampRequest): Promise<Buffer> {
    const { baseURL, timeout, retry } = this.options;
    const url = `${baseURL}/api/v1/timestamp`;

    const response = await fetchWithRetry(url, {
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      timeout,
      retry,
    });

    return response.buffer();
  }
}
