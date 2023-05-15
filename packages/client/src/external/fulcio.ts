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

import type { FetchOptions } from '../types/fetch';

export type FulcioOptions = {
  baseURL: string;
} & FetchOptions;

export interface SigningCertificateRequest {
  credentials: {
    oidcIdentityToken: string;
  };
  publicKeyRequest: {
    publicKey: {
      algorithm: string;
      content: string;
    };
    proofOfPossession: string;
  };
}

export interface SigningCertificateResponse {
  signedCertificateEmbeddedSct?: {
    chain: { certificates: string[] };
  };
  signedCertificateDetachedSct?: {
    chain: {
      certificates: string[];
    };
    signedCertificateTimestamp: string;
  };
}

/**
 * Fulcio API client.
 */
export class Fulcio {
  private fetch: FetchInterface;
  private baseUrl: string;

  constructor(options: FulcioOptions) {
    this.fetch = fetch.defaults({
      retry: options.retry,
      timeout: options.timeout,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': ua.getUserAgent(),
      },
    });
    this.baseUrl = options.baseURL;
  }

  public async createSigningCertificate(
    request: SigningCertificateRequest
  ): Promise<SigningCertificateResponse> {
    const url = `${this.baseUrl}/api/v2/signingCert`;

    const response = await this.fetch(url, {
      method: 'POST',
      body: JSON.stringify(request),
    });
    checkStatus(response);

    const data = await response.json();
    return data;
  }
}
