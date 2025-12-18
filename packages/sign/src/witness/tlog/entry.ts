/*
Copyright 2025 The Sigstore Authors.

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
import { PublicKeyDetails } from '@sigstore/protobuf-specs';
import { crypto, encoding as enc, json, pem } from '../../util';

import type { CreateEntryRequest } from '@sigstore/protobuf-specs/rekor/v2';
import type {
  ProposedDSSEEntry,
  ProposedEntry,
  ProposedHashedRekordEntry,
  ProposedIntotoEntry,
} from '../../external/rekor';
import type { SignatureBundle } from '../witness';

const SHA256_ALGORITHM = 'sha256';

export function toProposedEntry(
  content: SignatureBundle,
  publicKey: string,
  // TODO: Remove this parameter once have completely switched to 'dsse' entries
  entryType: 'dsse' | 'intoto' = 'dsse'
): ProposedEntry {
  switch (content.$case) {
    case 'dsseEnvelope':
      // TODO: Remove this conditional once have completely ditched "intoto" entries
      if (entryType === 'intoto') {
        return toProposedIntotoEntry(content.dsseEnvelope, publicKey);
      }
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
          algorithm: SHA256_ALGORITHM,
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

// Returns a properly formatted Rekor "intoto" entry for the given DSSE
// envelope and signature
function toProposedIntotoEntry(
  envelope: Envelope,
  publicKey: string
): ProposedIntotoEntry {
  // Calculate the value for the payloadHash field in the Rekor entry
  const payloadHash = crypto
    .digest(SHA256_ALGORITHM, envelope.payload)
    .toString('hex');

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
        hash: { algorithm: SHA256_ALGORITHM, value: envelopeHash },
        payloadHash: { algorithm: SHA256_ALGORITHM, value: payloadHash },
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

  return crypto
    .digest(SHA256_ALGORITHM, json.canonicalize(dsse))
    .toString('hex');
}

export function toCreateEntryRequest(
  content: SignatureBundle,
  publicKey: string
): CreateEntryRequest {
  switch (content.$case) {
    case 'dsseEnvelope':
      return toCreateEntryRequestDSSE(content.dsseEnvelope, publicKey);
    case 'messageSignature':
      return toCreateEntryRequestMessageSignature(
        content.messageSignature,
        publicKey
      );
  }
}

function toCreateEntryRequestDSSE(
  envelope: Envelope,
  publicKey: string
): CreateEntryRequest {
  return {
    spec: {
      $case: 'dsseRequestV002',
      dsseRequestV002: {
        envelope: envelope,
        verifiers: [
          {
            // TODO: We need to add support of passing the key details in the
            // signature bundle. For now we're hardcoding the key details here.
            keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
            verifier: {
              $case: 'x509Certificate',
              x509Certificate: {
                rawBytes: pem.toDER(publicKey),
              },
            },
          },
        ],
      },
    },
  };
}

function toCreateEntryRequestMessageSignature(
  messageSignature: MessageSignature,
  publicKey: string
): CreateEntryRequest {
  return {
    spec: {
      $case: 'hashedRekordRequestV002',
      hashedRekordRequestV002: {
        digest: messageSignature.messageDigest.digest,
        signature: {
          content: messageSignature.signature,
          verifier: {
            // TODO: We need to add support of passing the key details in the
            // signature bundle. For now we're hardcoding the key details here.
            keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
            verifier: {
              $case: 'x509Certificate',
              x509Certificate: {
                rawBytes: pem.toDER(publicKey),
              },
            },
          },
        },
      },
    },
  };
}
