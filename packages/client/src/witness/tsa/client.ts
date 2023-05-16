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
import { InternalError } from '../../error';
import { TimestampAuthority } from '../../external';
import { crypto } from '../../util';

import type { FetchOptions } from '../../types/fetch';

export interface TSA {
  createTimestamp: (signature: Buffer) => Promise<Buffer>;
}

export type TSAClientOptions = {
  tsaBaseURL: string;
} & FetchOptions;

export class TSAClient implements TSA {
  private tsa: TimestampAuthority;

  constructor(options: TSAClientOptions) {
    this.tsa = new TimestampAuthority({
      baseURL: options.tsaBaseURL,
      retry: options.retry,
      timeout: options.timeout,
    });
  }

  public async createTimestamp(signature: Buffer): Promise<Buffer> {
    const request = {
      artifactHash: crypto.hash(signature).toString('base64'),
      hashAlgorithm: 'sha256',
    };

    try {
      return await this.tsa.createTimestamp(request);
    } catch (err) {
      throw new InternalError({
        code: 'TSA_CREATE_TIMESTAMP_ERROR',
        message: 'error creating timestamp',
        cause: err,
      });
    }
  }
}
