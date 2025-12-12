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

import type {
  DSSELogEntryV002,
  Entry,
} from '@sigstore/protobuf-specs/rekor/v2';
import type { ProposedDSSEEntry } from '@sigstore/rekor-types';
import type { SignatureContent } from '../shared.types';

// Compare the given dsse tlog entry to the given bundle
export function verifyDSSETLogBody(
  tlogEntry: ProposedDSSEEntry,
  content: SignatureContent
): void {
  switch (tlogEntry.apiVersion) {
    case '0.0.1':
      return verifyDSSE001TLogBody(tlogEntry, content);
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported dsse version: ${tlogEntry.apiVersion}`,
      });
  }
}

// Compare the given dsse tlog entry to the given bundle. This function is
// specifically for Rekor V2 entries.
export function verifyDSSETLogBodyV2(
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
    case 'dsseV002':
      return verifyDSSE002TLogBody(spec.dsseV002, content);
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported version: ${spec.$case}`,
      });
  }
}

// Compare the given dsse v0.0.1 tlog entry to the given DSSE envelope.
function verifyDSSE001TLogBody(
  tlogEntry: Extract<ProposedDSSEEntry, { apiVersion: '0.0.1' }>,
  content: SignatureContent
): void {
  // Ensure the bundle's DSSE only contains a single signature
  if (tlogEntry.spec.signatures?.length !== 1) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'signature count mismatch',
    });
  }

  const tlogSig = tlogEntry.spec.signatures[0].signature;

  // Ensure that the signature in the bundle's DSSE matches tlog entry
  if (!content.compareSignature(Buffer.from(tlogSig, 'base64')))
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'tlog entry signature mismatch',
    });

  // Ensure the digest of the bundle's DSSE payload matches the digest in the
  // tlog entry
  const tlogHash = tlogEntry.spec.payloadHash?.value || '';

  if (!content.compareDigest(Buffer.from(tlogHash, 'hex'))) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'DSSE payload hash mismatch',
    });
  }
}

// Compare the given dsse v0.0.2 tlog entry to the given DSSE envelope.
function verifyDSSE002TLogBody(
  spec: DSSELogEntryV002,
  content: SignatureContent
): void {
  // Ensure the bundle's DSSE only contains a single signature
  if (spec.signatures?.length !== 1) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'signature count mismatch',
    });
  }

  const tlogSig = spec.signatures[0].content;

  // Ensure that the signature in the bundle's DSSE matches tlog entry
  if (!content.compareSignature(tlogSig))
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'tlog entry signature mismatch',
    });

  // Ensure the digest of the bundle's DSSE payload matches the digest in the
  // tlog entry
  const tlogHash = spec.payloadHash?.digest || Buffer.from('');

  if (!content.compareDigest(tlogHash)) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: 'DSSE payload hash mismatch',
    });
  }
}
