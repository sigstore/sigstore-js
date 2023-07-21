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
import { Envelope, MessageSignature, envelopeToJSON } from '@sigstore/bundle';
import { encoding as enc } from '../../util';

import type {
  ProposedDSSEEntry,
  ProposedEntry,
  ProposedHashedRekordEntry,
} from '../../external/rekor';
import type { SignatureBundle } from '../witness';

export function toProposedEntry(
  content: SignatureBundle,
  publicKey: string
): ProposedEntry {
  switch (content.$case) {
    case 'dsseEnvelope':
      return toProposedDSSEEntry(content.dsseEnvelope, publicKey);
    case 'messageSignature':
      return toProposedHashedRekordEntry(content.messageSignature, publicKey);
  }
}

// Returns a properly formatted Rekor "hashedrekord" entry for the given digest
// and signature
function toProposedHashedRekordEntry(
  messageSignature: MessageSignature,
  publicKey: string
): ProposedHashedRekordEntry {
  const hexDigest = messageSignature.messageDigest.digest.toString('hex');
  const b64Signature = messageSignature.signature.toString('base64');
  const b64Key = enc.base64Encode(publicKey);

  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: {
        hash: {
          algorithm: 'sha256',
          value: hexDigest,
        },
      },
      signature: {
        content: b64Signature,
        publicKey: {
          content: b64Key,
        },
      },
    },
  };
}

// Returns a properly formatted Rekor "dsse" entry for the given DSSE envelope
// and signature
function toProposedDSSEEntry(
  envelope: Envelope,
  publicKey: string
): ProposedDSSEEntry {
  const envelopeJSON = JSON.stringify(envelopeToJSON(envelope));
  const encodedKey = enc.base64Encode(publicKey);

  return {
    apiVersion: '0.0.1',
    kind: 'dsse',
    spec: {
      proposedContent: {
        envelope: envelopeJSON,
        verifiers: [encodedKey],
      },
    },
  };
}
