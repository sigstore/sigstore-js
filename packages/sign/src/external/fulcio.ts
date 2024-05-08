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
  private options: FulcioOptions;

  constructor(options: FulcioOptions) {
    this.options = options;
  }

  public async createSigningCertificate(
    request: SigningCertificateRequest
  ): Promise<SigningCertificateResponse> {
    const { baseURL, retry, timeout } = this.options;
    const url = `${baseURL}/api/v2/signingCert`;

    const response = await fetchWithRetry(url, {
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      timeout,
      retry,
    });

    return response.json();
  }
}
