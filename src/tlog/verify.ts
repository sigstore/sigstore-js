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
  InvalidBundleError,
  UnsupportedVersionError,
  VerificationError,
} from '../error';
import {
  Bundle,
  Envelope,
  MessageSignature,
  TransparencyLogEntry,
} from '../types/bundle';
import { crypto, encoding as enc, json, x509 } from '../util';
import { EntryKind, HashedRekordKind, IntotoKind } from './types';

const TLOG_MISMATCH_ERROR_MSG = 'bundle content and tlog entry do not match';

// Structure over which the tlog SET signature is generated
interface VerificationPayload {
  body: string;
  integratedTime: number;
  logIndex: number;
  logID: string;
}

// Verifies that all of the tlog entries in the given bundle.
export function verifyTLogEntries(
  bundle: Bundle,
  tlogKeys: Record<string, KeyObject>
): void {
  // Extract the signing cert bytes if available
  let signingCert: Buffer | undefined;
  if (bundle.verificationMaterial?.content?.$case === 'x509CertificateChain') {
    signingCert =
      bundle.verificationMaterial.content.x509CertificateChain.certificates[0]
        .rawBytes;
  }

  // Iterate over the tlog entries and verify each one
  bundle.verificationData?.tlogEntries.forEach((entry) => {
    verifyTLogBody(entry, bundle);
    verifyTLogSET(entry, tlogKeys);

    // If there is no signing certificate, we can't verify the integrated time
    if (signingCert) {
      verifyTLogIntegratedTime(entry, signingCert);
    }
  });
}

// Verfifies the SET for the given entry using the provided keys.
function verifyTLogSET(
  entry: TransparencyLogEntry,
  tlogKeys: Record<string, KeyObject>
): void {
  // Re-create the original Rekor verification payload
  const payload = toVerificationPayload(entry);

  // Canonicalize the payload and turn into a buffer for verification
  const data = Buffer.from(json.canonicalize(payload), 'utf8');

  // Find the public key for the transaction log which generated the SET
  const tlogKey = tlogKeys[payload.logID];
  if (!tlogKey) {
    throw new VerificationError('no key found for logID: ' + payload.logID);
  }

  // Extract the SET from the tlog entry
  const signature = entry.inclusionPromise?.signedEntryTimestamp;
  if (!signature || signature.length === 0) {
    throw new InvalidBundleError('no SET found in bundle');
  }

  if (!crypto.verifyBlob(data, tlogKey, signature)) {
    throw new VerificationError('transparency log SET verification failed');
  }
}

// Checks that the tlog integrated time is within the certificate's validity
// period.
function verifyTLogIntegratedTime(
  entry: TransparencyLogEntry,
  signingCert: Buffer
): void {
  const x509Cert = x509.parseCertificate(signingCert);
  const integratedTime = new Date(Number(entry.integratedTime) * 1000);

  if (integratedTime > x509Cert.validTo) {
    throw new VerificationError(
      'tlog integrated time is after certificate expiration'
    );
  }

  if (integratedTime < x509Cert.validFrom) {
    throw new VerificationError(
      'tlog integrated time is before certificate issuance'
    );
  }
}

// Compare the given intoto tlog entry to the given bundle
function verifyTLogBody(entry: TransparencyLogEntry, bundle: Bundle): void {
  if (!entry.kindVersion) {
    throw new InvalidBundleError('no kindVersion found in bundle');
  }

  const { kind, version } = entry.kindVersion;
  const body: EntryKind = JSON.parse(entry.canonicalizedBody.toString('utf8'));

  if (kind !== body.kind || version !== body.apiVersion) {
    throw new VerificationError(TLOG_MISMATCH_ERROR_MSG);
  }

  switch (body.kind) {
    case 'intoto':
      verifyIntotoTLogBody(body, bundle);
      break;
    case 'hashedrekord':
      verifyHashedRekordTLogBody(body, bundle);
      break;
    default:
      throw new UnsupportedVersionError(
        `unsupported kind in tlog entry: ${kind}`
      );
  }
}

// Compare the given intoto tlog entry to the given bundle
function verifyIntotoTLogBody(tlogEntry: IntotoKind, bundle: Bundle): void {
  if (bundle.content?.$case !== 'dsseEnvelope') {
    throw new UnsupportedVersionError(
      `unsupported bundle content: ${bundle.content?.$case || 'unknown'}`
    );
  }

  const dsse = bundle.content.dsseEnvelope;

  switch (tlogEntry.apiVersion) {
    case '0.0.2':
      verifyIntoto002TLogBody(tlogEntry, dsse);
      break;
    default:
      throw new UnsupportedVersionError(
        `unsupported intoto version: ${tlogEntry.apiVersion}`
      );
  }
}

// Compare the given hashedrekord tlog entry to the given bundle
function verifyHashedRekordTLogBody(
  tlogEntry: HashedRekordKind,
  bundle: Bundle
): void {
  if (bundle.content?.$case !== 'messageSignature') {
    throw new UnsupportedVersionError(
      `unsupported bundle content: ${bundle.content?.$case || 'unknown'}`
    );
  }

  const messageSignature = bundle.content.messageSignature;

  switch (tlogEntry.apiVersion) {
    case '0.0.1':
      verifyHashedrekor001TLogBody(tlogEntry, messageSignature);
      break;
    default:
      throw new UnsupportedVersionError(
        `unsupported hashedrekord version: ${tlogEntry.apiVersion}`
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
    throw new VerificationError(TLOG_MISMATCH_ERROR_MSG);
  }

  // Ensure that every signature in the bundle's DSSE is present in the tlog entry
  if (!dsseSigs.every((dsseSig) => tlogSigs.includes(dsseSig))) {
    throw new VerificationError(TLOG_MISMATCH_ERROR_MSG);
  }

  // Ensure the digest of the bundle's DSSE payload matches the digest in the
  // tlog entry
  const dssePayloadHash = crypto.hash(dsse.payload).toString('hex');

  if (dssePayloadHash !== tlogEntry.spec.content.payloadHash?.value) {
    throw new VerificationError(TLOG_MISMATCH_ERROR_MSG);
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
    throw new VerificationError(TLOG_MISMATCH_ERROR_MSG);
  }

  // Ensure that the bundle's message digest matches the tlog entry
  const msgDigest = messageSignature.messageDigest?.digest.toString('hex');
  const tlogDigest = tlogEntry.spec.data.hash?.value;

  if (msgDigest !== tlogDigest) {
    throw new VerificationError(TLOG_MISMATCH_ERROR_MSG);
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
    throw new InvalidBundleError('no logId found in bundle');
  }

  return {
    body: canonicalizedBody.toString('base64'),
    integratedTime: Number(integratedTime),
    logIndex: Number(logIndex),
    logID: logId.keyId.toString('hex'),
  };
}
