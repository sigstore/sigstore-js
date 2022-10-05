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
import { CertificateRequest } from '../types/fulcio';
import { ua } from '../util';
import { checkStatus } from './error';

const DEFAULT_BASE_URL = 'https://fulcio.sigstore.dev';

export interface FulcioOptions {
  baseURL?: string;
}

/**
 * Fulcio API client.
 */
export class Fulcio {
  private fetch: FetchInterface;
  private baseUrl: string;

  constructor(options: FulcioOptions) {
    this.fetch = fetch.defaults({
      retry: { retries: 2 },
      timeout: 5000,
      headers: {
        Accept: 'application/pem-certificate-chain',
        'Content-Type': 'application/json',
        'User-Agent': ua.getUserAgent(),
      },
    });
    this.baseUrl = options.baseURL ?? DEFAULT_BASE_URL;
  }

  public async createSigningCertificate(
    idToken: string,
    request: CertificateRequest
  ): Promise<string> {
    const url = `${this.baseUrl}/api/v1/signingCert`;

    const response = await this.fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${idToken}` },
      body: JSON.stringify(request),
    });
    checkStatus(response);

    const data = await response.text();
    return data;
  }
}
