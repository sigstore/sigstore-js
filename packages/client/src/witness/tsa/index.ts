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
import { TSA, TSAClient, TSAClientOptions } from './client';

import type { Affidavit, SignatureBundle, Witness } from '../witness';

export type TSAWitnessOptions = TSAClientOptions;

export class TSAWitness implements Witness {
  private tsa: TSA;

  constructor(options: TSAWitnessOptions) {
    this.tsa = new TSAClient({
      tsaBaseURL: options.tsaBaseURL,
      retry: options.retry,
      timeout: options.timeout,
    });
  }

  public async testify(content: SignatureBundle): Promise<Affidavit> {
    const signature = extractSignature(content);
    const timestamp = await this.tsa.createTimestamp(signature);
    return affidavit(timestamp);
  }
}

function extractSignature(content: SignatureBundle) {
  switch (content.$case) {
    case 'dsseEnvelope':
      return content.dsseEnvelope.signatures[0].sig;
    case 'messageSignature':
      return content.messageSignature.signature;
  }
}

function affidavit(timestamp: Buffer): Affidavit {
  return {
    rfc3161Timestamps: [{ signedTimestamp: timestamp }],
  };
}
