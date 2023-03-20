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
import { KeyObject } from 'crypto';
import { Fulcio } from '../client';
import { InternalError } from '../error';
import { toCertificateRequest } from './format';

export interface CA {
  createSigningCertificate: (
    identityToken: string,
    publicKey: KeyObject,
    challenge: Buffer
  ) => Promise<string[]>;
}

export interface CAClientOptions {
  fulcioBaseURL: string;
}

export class CAClient implements CA {
  private fulcio: Fulcio;

  constructor(options: CAClientOptions) {
    this.fulcio = new Fulcio({ baseURL: options.fulcioBaseURL });
  }

  public async createSigningCertificate(
    identityToken: string,
    publicKey: KeyObject,
    challenge: Buffer
  ): Promise<string[]> {
    const request = toCertificateRequest(identityToken, publicKey, challenge);

    try {
      const certificate = await this.fulcio.createSigningCertificate(request);

      return certificate.signedCertificateEmbeddedSct.chain.certificates;
    } catch (err) {
      throw new InternalError('error creating signing certificate', err);
    }
  }
}
