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
import { VerificationError } from '../../error';
import * as sigstore from '../../types/sigstore';
import { crypto, encoding as enc } from '../../util';

import type {
  ProposedEntry,
  ProposedDSSEEntry,
  ProposedHashedRekordEntry,
  ProposedIntotoEntry,
} from '../../external/rekor';

const TLOG_MISMATCH_ERROR_MSG = 'bundle content and tlog entry do not match';

// Compare the given tlog entry to the given bundle
export function verifyTLogBody(
  entry: sigstore.VerifiableTransparencyLogEntry,
  bundleContent: sigstore.Bundle['content']
): boolean {
  const { kind, version } = entry.kindVersion;
  const body: ProposedEntry = JSON.parse(
    entry.canonicalizedBody.toString('utf8')
  );

  try {
    if (kind !== body.kind || version !== body.apiVersion) {
      throw new VerificationError(TLOG_MISMATCH_ERROR_MSG);
    }

    switch (body.kind) {
      case 'dsse':
        verifyDSSETLogBody(body, bundleContent);
        break;
      case 'intoto':
        verifyIntotoTLogBody(body, bundleContent);
        break;
      case 'hashedrekord':
        verifyHashedRekordTLogBody(body, bundleContent);
        break;
      default:
        throw new VerificationError(`unsupported kind in tlog entry: ${kind}`);
    }
    return true;
  } catch (e) {
    return false;
  }
}

// Compare the given intoto tlog entry to the given bundle
function verifyDSSETLogBody(
  tlogEntry: ProposedDSSEEntry,
  content: sigstore.Bundle['content']
): void {
  if (content?.$case !== 'dsseEnvelope') {
    throw new VerificationError(
      `unsupported bundle content: ${content?.$case || 'unknown'}`
    );
  }

  const dsse = content.dsseEnvelope;

  switch (tlogEntry.apiVersion) {
    case '0.0.1':
      verifyDSSE001TLogBody(tlogEntry, dsse);
      break;
    default:
      throw new VerificationError(
        `unsupported dsse version: ${tlogEntry.apiVersion}`
      );
  }
}

// Compare the given intoto tlog entry to the given bundle
function verifyIntotoTLogBody(
  tlogEntry: ProposedIntotoEntry,
  content: sigstore.Bundle['content']
): void {
  if (content?.$case !== 'dsseEnvelope') {
    throw new VerificationError(
      `unsupported bundle content: ${content?.$case || 'unknown'}`
    );
  }

  const dsse = content.dsseEnvelope;

  switch (tlogEntry.apiVersion) {
    case '0.0.2':
      verifyIntoto002TLogBody(tlogEntry, dsse);
      break;
    default:
      throw new VerificationError(
        `unsupported intoto version: ${tlogEntry.apiVersion}`
      );
  }
}

// Compare the given hashedrekord tlog entry to the given bundle
function verifyHashedRekordTLogBody(
  tlogEntry: ProposedHashedRekordEntry,
  content: sigstore.Bundle['content']
): void {
  if (content?.$case !== 'messageSignature') {
    throw new VerificationError(
      `unsupported bundle content: ${content?.$case || 'unknown'}`
    );
  }

  const messageSignature = content.messageSignature;

  switch (tlogEntry.apiVersion) {
    case '0.0.1':
      verifyHashedrekor001TLogBody(tlogEntry, messageSignature);
      break;
    default:
      throw new VerificationError(
        `unsupported hashedrekord version: ${tlogEntry.apiVersion}`
      );
  }
}

// Compare the given dsse v0.0.1 tlog entry to the given DSSE envelope.
function verifyDSSE001TLogBody(
  tlogEntry: Extract<ProposedDSSEEntry, { apiVersion: '0.0.1' }>,
  dsse: sigstore.Envelope
): void {
  // Collect all of the signatures from the DSSE envelope
  // Turns them into base64-encoded strings for comparison
  const dsseSigs = dsse.signatures.map((signature) =>
    signature.sig.toString('base64')
  );

  // Collect all of the signatures from the tlog entry
  // Remember that tlog signatures are double base64-encoded
  const tlogSigs = tlogEntry.spec.signatures?.map((signature) =>
    signature.signature ? enc.base64Decode(signature.signature) : ''
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

  if (dssePayloadHash !== tlogEntry.spec.payloadHash?.value) {
    throw new VerificationError(TLOG_MISMATCH_ERROR_MSG);
  }
}

// Compare the given intoto v0.0.2 tlog entry to the given DSSE envelope.
function verifyIntoto002TLogBody(
  tlogEntry: Extract<ProposedIntotoEntry, { apiVersion: '0.0.2' }>,
  dsse: sigstore.Envelope
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
  tlogEntry: Extract<ProposedHashedRekordEntry, { apiVersion: '0.0.1' }>,
  messageSignature: sigstore.MessageSignature
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
