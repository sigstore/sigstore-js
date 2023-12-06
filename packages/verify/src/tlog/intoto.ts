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
import { VerificationError } from '../error';

import type { ProposedIntotoEntry } from '@sigstore/rekor-types';
import type { SignatureContent } from '../shared.types';

// Compare the given intoto tlog entry to the given bundle
export function verifyIntotoTLogBody(
  tlogEntry: ProposedIntotoEntry,
  content: SignatureContent
): void {
  switch (tlogEntry.apiVersion) {
    case '0.0.2':
      return verifyIntoto002TLogBody(tlogEntry, content);
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported intoto version: ${tlogEntry.apiVersion}`,
      });
  }
}

// Compare the given intoto v0.0.2 tlog entry to the given DSSE envelope.
function verifyIntoto002TLogBody(
  tlogEntry: Extract<ProposedIntotoEntry, { apiVersion: '0.0.2' }>,
  content: SignatureContent
): void {
  // Ensure the bundle's DSSE contains a single signature
  if (tlogEntry.spec.content.envelope.signatures?.length !== 1) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'signature count mismatch',
    });
  }

  // Signature is double-base64-encoded in the tlog entry
  const tlogSig = base64Decode(
    tlogEntry.spec.content.envelope.signatures[0].sig
  );

  // Ensure that the signature in the bundle's DSSE matches tlog entry
  if (!content.compareSignature(Buffer.from(tlogSig, 'base64')))
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'tlog entry signature mismatch',
    });

  // Ensure the digest of the bundle's DSSE payload matches the digest in the
  // tlog entry
  const tlogHash = tlogEntry.spec.content.payloadHash?.value || '';

  if (!content.compareDigest(Buffer.from(tlogHash, 'hex'))) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'DSSE payload hash mismatch',
    });
  }
}

function base64Decode(str: string): string {
  return Buffer.from(str, 'base64').toString('utf-8');
}
