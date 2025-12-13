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
import { Entry } from '@sigstore/protobuf-specs/rekor/v2';
import { VerificationError } from '../error';
import { verifyDSSETLogBody, verifyDSSETLogBodyV2 } from './dsse';
import {
  verifyHashedRekordTLogBody,
  verifyHashedRekordTLogBodyV2,
} from './hashedrekord';
import { verifyIntotoTLogBody } from './intoto';

import type {
  TLogEntryWithInclusionPromise,
  TLogEntryWithInclusionProof,
  TransparencyLogEntry,
} from '@sigstore/bundle';
import type { SignatureContent } from '../shared.types';
import { TLogAuthority } from '../trust';
import { verifyCheckpoint } from './checkpoint';
import { verifyMerkleInclusion } from './merkle';
import { verifyTLogSET } from './set';

// Verifies that the given tlog entry matches the supplied signature content.
export function verifyTLogBody(
  entry: TransparencyLogEntry,
  sigContent: SignatureContent
): void {
  const { kind, version } = entry.kindVersion;
  const body = JSON.parse(entry.canonicalizedBody.toString('utf8'));

  // validate body
  if (kind !== body.kind || version !== body.apiVersion) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: `kind/version mismatch - expected: ${kind}/${version}, received: ${body.kind}/${body.apiVersion}`,
    });
  }

  switch (kind) {
    case 'dsse':
      // Rekor V1 and V2 use incompatible types so we need to branch here based on version
      if (version == '0.0.1') {
        return verifyDSSETLogBody(body, sigContent);
      } else {
        const entryRekorV2 = Entry.fromJSON(body);
        return verifyDSSETLogBodyV2(entryRekorV2, sigContent);
      }
    case 'intoto':
      return verifyIntotoTLogBody(body, sigContent);
    case 'hashedrekord':
      // Rekor V1 and V2 use incompatible types so we need to branch here based on version
      if (version == '0.0.1') {
        return verifyHashedRekordTLogBody(body, sigContent);
      } else {
        const entryRekorV2 = Entry.fromJSON(body);
        return verifyHashedRekordTLogBodyV2(entryRekorV2, sigContent);
      }
    /* istanbul ignore next */
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported kind: ${kind}`,
      });
  }
}

export function verifyTLogInclusion(
  entry: TransparencyLogEntry,
  tlogAuthorities: TLogAuthority[]
): void {
  let inclusionVerified = false;

  if (isTLogEntryWithInclusionPromise(entry)) {
    verifyTLogSET(entry, tlogAuthorities);
    inclusionVerified = true;
  }

  if (isTLogEntryWithInclusionProof(entry)) {
    const checkpoint = verifyCheckpoint(entry, tlogAuthorities);
    verifyMerkleInclusion(entry, checkpoint);
    inclusionVerified = true;
  }

  if (!inclusionVerified) {
    throw new VerificationError({
      code: 'TLOG_MISSING_INCLUSION_ERROR',
      message: 'inclusion could not be verified',
    });
  }

  return;
}

function isTLogEntryWithInclusionPromise(
  entry: TransparencyLogEntry
): entry is TLogEntryWithInclusionPromise {
  return entry.inclusionPromise !== undefined;
}

function isTLogEntryWithInclusionProof(
  entry: TransparencyLogEntry
): entry is TLogEntryWithInclusionProof {
  return entry.inclusionProof !== undefined;
}
