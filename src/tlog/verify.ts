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
import {
  Bundle,
  Envelope,
  MessageSignature,
  TransparencyLogEntry,
} from '../types/bundle';
import { crypto, encoding as enc, json, x509 } from '../util';
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
  tlogKeys: Record<string, KeyObject>
): void {
  bundle.verificationData?.tlogEntries.forEach((entry) => {
    // Re-create the original Rekor verification payload
    const payload = toVerificationPayload(entry);

    // Canonicalize the payload and turn into a buffer for verification
    const data = Buffer.from(json.canonicalize(payload), 'utf8');

    // Find the public key for the transaction log which generated the SET
    const tlogKey = tlogKeys[payload.logID];
    if (!tlogKey) {
      throw new Error('no key found for logID: ' + payload.logID);
    }

    // Extract the SET from the tlog entry
    const signature = entry.inclusionPromise?.signedEntryTimestamp;
    if (!signature || signature.length === 0) {
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

export function verifyTLogBodies(bundle: Bundle): void {
  bundle.verificationData?.tlogEntries.forEach((entry) => {
    verifyTLogBody(entry, bundle);
  });
}

// Compare the given intoto tlog entry to the given bundle
function verifyTLogBody(entry: TransparencyLogEntry, bundle: Bundle): void {
  if (!entry.kindVersion) {
    throw new Error('no kindVersion found in bundle');
  }

  const { kind, version } = entry.kindVersion;
  const body: EntryKind = JSON.parse(entry.canonicalizedBody.toString('utf8'));

  if (kind !== body.kind || version !== body.apiVersion) {
    throw new Error('bundle content and tlog entry do not match');
  }

  switch (body.kind) {
    case 'intoto':
      verifyIntotoTLogBody(body, bundle);
      break;
    case 'hashedrekord':
      verifyHashedRekordTLogBody(body, bundle);
      break;
    default:
      throw new Error('Unknown kind found in tlog entry');
  }
}

// Compare the given intoto tlog entry to the given bundle
function verifyIntotoTLogBody(tlogEntry: IntotoKind, bundle: Bundle): void {
  if (bundle.content?.$case !== 'dsseEnvelope') {
    throw new Error('bundle content and tlog entry do not match');
  }

  const dsse = bundle.content.dsseEnvelope;

  switch (tlogEntry.apiVersion) {
    case '0.0.2':
      verifyIntoto002TLogBody(tlogEntry, dsse);
      break;
    default:
      throw new Error('Unsupported intoto version: ' + tlogEntry.apiVersion);
  }
}

// Compare the given hashedrekord tlog entry to the given bundle
function verifyHashedRekordTLogBody(
  tlogEntry: HashedRekordKind,
  bundle: Bundle
): void {
  if (bundle.content?.$case !== 'messageSignature') {
    throw new Error('bundle content and tlog entry do not match');
  }

  const messageSignature = bundle.content.messageSignature;

  switch (tlogEntry.apiVersion) {
    case '0.0.1':
      verifyHashedrekor001TLogBody(tlogEntry, messageSignature);
      break;
    default:
      throw new Error(
        'Unsupported hashedrekord version: ' + tlogEntry.apiVersion
      );
  }
}

// Compare the given intoto v0.0.2 tlog entry to the given DSSE envelope.
function verifyIntoto002TLogBody(
  tlogEntry: Extract<IntotoKind, { apiVersion: '0.0.2' }>,
  dsse: Envelope
): void {
  // Collect all of the signatures from the DSSE envelope
  // Turns them into base64-encoded strings for comparison
  const dsseSigs = dsse.signatures.map((signature) =>
    signature.sig.toString('base64')
  );

  // Collect all of the signatures from the tlog entry
  // Remember that tlog signastures are double base64-encoded
  const tlogSigs = tlogEntry.spec.content.envelope?.signatures.map(
    (signature) => (signature.sig ? enc.base64Decode(signature.sig) : '')
  );

  // Ensure the bundle's DSSE and the tlog entry contain the same number of signatures
  if (dsseSigs.length !== tlogSigs?.length) {
    throw new Error('bundle content and tlog entry do not match');
  }

  // Ensure that every signature in the bundle's DSSE is present in the tlog entry
  if (!dsseSigs.every((dsseSig) => tlogSigs.includes(dsseSig))) {
    throw new Error('bundle content and tlog entry do not match');
  }

  // Ensure the digest of the bundle's DSSE payload matches the digest in the
  // tlog entry
  const dssePayloadHash = crypto.hash(dsse.payload).toString('hex');

  if (dssePayloadHash !== tlogEntry.spec.content.payloadHash?.value) {
    throw new Error('bundle content and tlog entry do not match');
  }
}

// Compare the given hashedrekord v0.0.1 tlog entry to the given message
// signature
function verifyHashedrekor001TLogBody(
  tlogEntry: Extract<HashedRekordKind, { apiVersion: '0.0.1' }>,
  messageSignature: MessageSignature
): void {
  // Ensure that the bundles message signature matches the tlog entry
  const msgSig = messageSignature.signature.toString('base64');
  const tlogSig = tlogEntry.spec.signature.content;

  if (msgSig !== tlogSig) {
    throw new Error('bundle content and tlog entry do not match');
  }

  // Ensure that the bundle's message digest matches the tlog entry
  const msgDigest = messageSignature.messageDigest?.digest.toString('hex');
  const tlogDigest = tlogEntry.spec.data.hash?.value;

  if (msgDigest !== tlogDigest) {
    throw new Error('bundle content and tlog entry do not match');
  }
}

// Returns a properly formatted "VerificationPayload" for one of the
// transaction log entires in the given bundle which can be used for SET
// verification.
function toVerificationPayload(
  entry: TransparencyLogEntry
): VerificationPayload {
  // Rekor metadata
  const { integratedTime, logIndex, logId, canonicalizedBody } = entry;

  if (!logId) {
    throw new Error('no logId found in bundle');
  }

  return {
    body: canonicalizedBody.toString('base64'),
    integratedTime: Number(integratedTime),
    logIndex: Number(logIndex),
    logID: logId.keyId.toString('hex'),
  };
}
