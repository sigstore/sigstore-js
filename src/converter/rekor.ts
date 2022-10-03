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
import { DSSE } from '../bundle';
import { HashedRekordKind, IntotoKind } from '../client/rekor';
import * as crypto from '../crypto';
import * as enc from '../encoding';

export const request = {
  toProposedIntotoEntry: (envelope: DSSE, certificate: string): IntotoKind => {
    const payload = enc.base64Encode(envelope.payload);
    const signature = enc.base64Encode(envelope.signatures[0].sig);
    const b64Certificate = enc.base64Encode(certificate);
    const hash = crypto.hash(JSON.stringify(envelope.payload));

    return {
      apiVersion: '0.0.2',
      kind: 'intoto',
      spec: {
        content: {
          envelope: {
            payloadType: envelope.payloadType,
            payload: payload,
            signatures: [
              { keyid: '', sig: signature, publicKey: b64Certificate },
            ],
          },
          hash: { algorithm: 'sha256', value: hash },
        },
      },
    };
  },

  toProposedHashedRekordEntry: (
    digest: string,
    signature: string,
    certificate: string
  ): HashedRekordKind => {
    const b64Certificate = enc.base64Encode(certificate);

    return {
      apiVersion: '0.0.1',
      kind: 'hashedrekord',
      spec: {
        data: {
          hash: {
            algorithm: 'sha256',
            value: digest,
          },
        },
        signature: {
          content: signature,
          publicKey: {
            content: b64Certificate,
          },
        },
      },
    };
  },
};
