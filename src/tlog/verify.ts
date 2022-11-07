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
import { Bundle, Envelope, MessageSignature } from '../types/bundle';
import { SignatureMaterial } from '../types/signature';
import { crypto, encoding as enc, json, x509 } from '../util';
import { toProposedHashedRekordEntry, toProposedIntotoEntry } from './format';
import {
  EntryKind,
  HashedRekordKind,
  IntotoKind,
  VerificationPayload,
} from './types';

// Verifies that all of the tlog entries in the given bundle can be verified.
// Verification is peroformed by re-creating the original Rekor entry from the
// bundle and then verifying the SET against the entry using the corresponding
// key.
export function verifyTLogSET(
  bundle: Bundle,
  publicKey: string,
  tlogKeys: Record<string, KeyObject>
): void {
  bundle.verificationData?.tlogEntries.forEach((entry, index) => {
    // Re-create the original Rekor verification payload
    const payload = toVerificationPayload(bundle, publicKey, index);

    // Canonicalize the payload and turn into a buffer for verification
    const data = Buffer.from(json.canonicalize(payload), 'utf8');

    // Find the public key for the transaction log which generated the SET
    const tlogKey = tlogKeys[payload.logID];
    if (!tlogKey) {
      throw new Error('no key found for logID: ' + payload.logID);
    }

    // Extract the SET from the tlog entry
    const signature = entry.inclusionPromise?.signedEntryTimestamp;
    if (!signature) {
      throw new Error('no SET found in bundle');
    }

    if (!crypto.verifyBlob(data, tlogKey, signature)) {
      throw new Error('transparency log SET verification failed');
    }
  });
}

export function verifyTLogIntegratedTime(bundle: Bundle): void {
  if (bundle.verificationMaterial?.content?.$case !== 'x509CertificateChain') {
    // If there is no certificate, we can't verify the integrated time
    return;
  }

  // Get a parsed certificate from the DER bytes in the bundle
  const der =
    bundle.verificationMaterial.content.x509CertificateChain.certificates[0]
      .rawBytes;
  const cert = x509.parseCertificate(der);

  // Iterate over all of the tlog entries in the bundle
  bundle.verificationData?.tlogEntries.forEach((entry) => {
    const integratedTime = new Date(Number(entry.integratedTime) * 1000);

    if (integratedTime > cert.validTo) {
      throw new Error('tlog integrated time is after certificate expiration');
    }

    if (integratedTime < cert.validFrom) {
      throw new Error('tlog integrated time is before certificate issuance');
    }
  });
}

// Returns a properly formatted "VerificationPayload" for one of the
// transaction log entires in the given bundle which can be used for SET
// verification.
function toVerificationPayload(
  bundle: Bundle,
  publicKey: string,
  index = 0
): VerificationPayload {
  // Ensure bundle has tlog entries
  const entries = bundle.verificationData?.tlogEntries;
  if (!entries || entries.length - 1 < index) {
    throw new Error('No tlog entries found in bundle');
  }

  // Rekor metadata
  const { integratedTime, logIndex, logId } = entries[index];

  if (!logId) {
    throw new Error('No logId found in bundle');
  }

  // Recreate the Rekor entry from the bundle
  const body = toVerificationBody(bundle, publicKey);

  return {
    body: enc.base64Encode(json.canonicalize(body)),
    integratedTime: Number(integratedTime),
    logIndex: Number(logIndex),
    logID: logId.keyId.toString('hex'),
  };
}

// Recreates the original Rekor entry from the bundle.
function toVerificationBody(bundle: Bundle, publicKey: string): EntryKind {
  switch (bundle.content?.$case) {
    case 'messageSignature': {
      return toMessageSignatureVerificationBody(
        bundle.content.messageSignature,
        publicKey
      );
    }
    case 'dsseEnvelope': {
      return toDSSEVerificationBody(bundle.content.dsseEnvelope, publicKey);
    }
    default:
      throw new Error('Unsupported bundle type');
  }
}

// Recreates a Rekor "hashedrekord" entry from the bundle.
function toMessageSignatureVerificationBody(
  messageSignature: MessageSignature,
  certificate: string
): HashedRekordKind {
  const digest = messageSignature.messageDigest?.digest || Buffer.from('');
  const sig = messageSignature.signature;
  const sigMaterial: SignatureMaterial = {
    signature: sig,
    certificates: [certificate],
    key: undefined,
  };

  return toProposedHashedRekordEntry(digest, sigMaterial);
}

// Recreates a Rekor "intoto" entry from the bundle.
function toDSSEVerificationBody(
  dsseEnvelope: Envelope,
  certificate: string
): IntotoKind {
  const sig = dsseEnvelope.signatures[0].sig;
  const sigMaterial: SignatureMaterial = {
    signature: sig,
    certificates: [certificate],
    key: undefined,
  };

  const body = toProposedIntotoEntry(dsseEnvelope, sigMaterial);

  // When Rekor saves the entry it removes the payload from the envelope
  if (body.apiVersion === '0.0.2') {
    delete body.spec.content?.envelope?.payload;
  }

  return body;
}
