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
import { Envelope, MessageSignature } from '@sigstore/bundle';
import { crypto, encoding as enc, json } from '../../util';

import type {
  ProposedEntry,
  ProposedHashedRekordEntry,
  ProposedIntotoEntry,
} from '../../external/rekor';
import type { SignatureBundle } from '../witness';

export function toProposedEntry(
  content: SignatureBundle,
  publicKey: string
): ProposedEntry {
  switch (content.$case) {
    case 'dsseEnvelope':
      return toProposedIntotoEntry(content.dsseEnvelope, publicKey);
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

// Returns a properly formatted Rekor "intoto" entry for the given DSSE
// envelope and signature
function toProposedIntotoEntry(
  envelope: Envelope,
  publicKey: string
): ProposedIntotoEntry {
  // Calculate the value for the payloadHash field in the Rekor entry
  const payloadHash = crypto.hash(envelope.payload).toString('hex');

  // Calculate the value for the hash field in the Rekor entry
  const envelopeHash = calculateDSSEHash(envelope, publicKey);

  // Collect values for re-creating the DSSE envelope.
  // Double-encode payload and signature cause that's what Rekor expects
  const payload = enc.base64Encode(envelope.payload.toString('base64'));
  const sig = enc.base64Encode(envelope.signatures[0].sig.toString('base64'));
  const keyid = envelope.signatures[0].keyid;
  const encodedKey = enc.base64Encode(publicKey);

  // Create the envelope portion of the entry. Note the inclusion of the
  // publicKey in the signature struct is not a standard part of a DSSE
  // envelope, but is required by Rekor.
  const dsse: ProposedIntotoEntry['spec']['content']['envelope'] = {
    payloadType: envelope.payloadType,
    payload: payload,
    signatures: [{ sig, publicKey: encodedKey }],
  };

  // If the keyid is an empty string, Rekor seems to remove it altogether. We
  // need to do the same here so that we can properly recreate the entry for
  // verification.
  if (keyid.length > 0) {
    dsse.signatures[0].keyid = keyid;
  }

  return {
    apiVersion: '0.0.2',
    kind: 'intoto',
    spec: {
      content: {
        envelope: dsse,
        hash: { algorithm: 'sha256', value: envelopeHash },
        payloadHash: { algorithm: 'sha256', value: payloadHash },
      },
    },
  };
}

// Calculates the hash of a DSSE envelope for inclusion in a Rekor entry.
// There is no standard way to do this, so the scheme we're using as as
// follows:
//  * payload is base64 encoded
//  * signature is base64 encoded (only the first signature is used)
//  * keyid is included ONLY if it is NOT an empty string
//  * The resulting JSON is canonicalized and hashed to a hex string
function calculateDSSEHash(envelope: Envelope, publicKey: string): string {
  const dsse: ProposedIntotoEntry['spec']['content']['envelope'] = {
    payloadType: envelope.payloadType,
    payload: envelope.payload.toString('base64'),
    signatures: [
      { sig: envelope.signatures[0].sig.toString('base64'), publicKey },
    ],
  };

  // If the keyid is an empty string, Rekor seems to remove it altogether.
  if (envelope.signatures[0].keyid.length > 0) {
    dsse.signatures[0].keyid = envelope.signatures[0].keyid;
  }

  return crypto.hash(json.canonicalize(dsse)).toString('hex');
}
