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
import { VerificationError } from '../error';

import {
  Entry,
  HashedRekordLogEntryV002,
} from '@sigstore/protobuf-specs/rekor/v2';
import type { ProposedHashedRekordEntry } from '@sigstore/rekor-types';
import type { SignatureContent } from '../shared.types';

export const HASHEDREKORD_API_VERSION_V1 = '0.0.1';

// Compare the given hashedrekord tlog entry to the given bundle
export function verifyHashedRekordTLogBody(
  tlogEntry: ProposedHashedRekordEntry,
  content: SignatureContent
): void {
  switch (tlogEntry.apiVersion) {
    case HASHEDREKORD_API_VERSION_V1:
      return verifyHashedrekord001TLogBody(tlogEntry, content);
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported hashedrekord version: ${tlogEntry.apiVersion}`,
      });
  }
}

// Compare the given hashedrekor tlog entry to the given bundle. This function is
// specifically for Rekor V2 entries.
export function verifyHashedRekordTLogBodyV2(
  tlogEntry: Entry,
  content: SignatureContent
): void {
  const spec = tlogEntry.spec?.spec;
  if (!spec) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: `missing dsse spec`,
    });
  }

  switch (spec.$case) {
    case 'hashedRekordV002':
      return verifyHashedrekord002TLogBody(spec.hashedRekordV002, content);
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported version: ${spec.$case}`,
      });
  }
}

// Compare the given hashedrekord v0.0.1 tlog entry to the given message
// signature
function verifyHashedrekord001TLogBody(
  tlogEntry: Extract<ProposedHashedRekordEntry, { apiVersion: '0.0.1' }>,
  content: SignatureContent
): void {
  // Ensure that the bundles message signature matches the tlog entry
  const tlogSig = tlogEntry.spec.signature.content || '';

  if (!content.compareSignature(Buffer.from(tlogSig, 'base64'))) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'signature mismatch',
    });
  }

  // Ensure that the bundle's message digest matches the tlog entry
  const tlogDigest = tlogEntry.spec.data.hash?.value || '';

  if (!content.compareDigest(Buffer.from(tlogDigest, 'hex'))) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'digest mismatch',
    });
  }
}

// Compare the given hashedrekord v0.0.2 tlog entry to the given message
// signature
function verifyHashedrekord002TLogBody(
  spec: HashedRekordLogEntryV002,
  content: SignatureContent
): void {
  // Ensure that the bundles message signature matches the tlog entry
  const tlogSig = spec.signature?.content || Buffer.from('');

  if (!content.compareSignature(tlogSig)) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'signature mismatch',
    });
  }

  // Ensure that the bundle's message digest matches the tlog entry
  const tlogHash = spec.data?.digest || Buffer.from('');

  if (!content.compareDigest(tlogHash)) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'digest mismatch',
    });
  }
}
