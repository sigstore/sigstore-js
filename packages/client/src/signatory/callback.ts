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
import { SignatureError } from '../error';

import type { SignerFunc } from '../types/signature';
import type { Endorsement, Signatory } from './signatory';

// The SignerFunc type is kinda janky, but it's already part of  the public
// API, so we'll live with it for now.
export type { SignerFunc };

export type CallbackSignerOptions = {
  signer: SignerFunc;
};

// Signatory implementation which uses a callback function to sign artifacts.
export class CallbackSigner implements Signatory {
  private signer: SignerFunc;

  constructor(options: CallbackSignerOptions) {
    this.signer = options.signer;
  }

  public async sign(data: Buffer): Promise<Endorsement> {
    const sigMaterial = await this.signer(data);

    // Since we're getting data from an external source, we need to validate
    // that it's well-formed and complete.
    if (!sigMaterial.signature) {
      throw new SignatureError({
        code: 'MISSING_SIGNATURE_ERROR',
        message: 'no signature returned from signer',
      });
    }

    if (!sigMaterial.key) {
      throw new SignatureError({
        code: 'MISSING_PUBLIC_KEY_ERROR',
        message: 'no key returned from signer',
      });
    }

    return {
      signature: sigMaterial.signature,
      key: {
        $case: 'publicKey',
        hint: sigMaterial.key.id,
        publicKey: sigMaterial.key.value,
      },
    };
  }
}
