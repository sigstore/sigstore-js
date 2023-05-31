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
import crypto, { KeyPairKeyObjectResult } from 'crypto';

import type { Endorsement, Signatory } from '../signatory';

const EC_KEYPAIR_TYPE = 'ec';
const P256_CURVE = 'P-256';

// Signatory implementation which uses an ephemeral keypair to sign artifacts.
// The private key lives only in memory and is tied to the lifetime of the
// EphemeralSigner instance.
export class EphemeralSigner implements Signatory {
  private keypair: KeyPairKeyObjectResult;

  constructor() {
    this.keypair = crypto.generateKeyPairSync(EC_KEYPAIR_TYPE, {
      namedCurve: P256_CURVE,
    });
  }

  public async sign(data: Buffer): Promise<Endorsement> {
    const signature = crypto.sign(null, data, this.keypair.privateKey);
    const publicKey = this.keypair.publicKey
      .export({ format: 'pem', type: 'spki' })
      .toString('ascii');

    return {
      signature: signature,
      key: { $case: 'publicKey', publicKey },
    };
  }
}
