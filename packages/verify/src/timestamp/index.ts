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
import type { RFC3161Timestamp } from '@sigstore/core';
import assert from 'assert';
import { VerificationError } from '../error';
import { verifyCheckpoint } from './checkpoint';
import { verifyMerkleInclusion } from './merkle';
import { verifyTLogSET } from './set';

import type {
  TLogEntryWithInclusionPromise,
  TLogEntryWithInclusionProof,
  TransparencyLogEntry,
} from '@sigstore/bundle';
import type { CertAuthority, TLogAuthority } from '../trust';

export type TimestampType = 'transparency-log' | 'timestamp-authority';

export type TimestampVerificationResult = {
  type: TimestampType;
  logID: Buffer;
  timestamp: Date;
};

export function verifyTSATimestamp(
  timestamp: RFC3161Timestamp,
  timestampAuthorities: CertAuthority[]
): TimestampVerificationResult {
  // TODO: Insert TSA verification logic here.
  assert(timestampAuthorities);
  return {
    logID: timestamp.signerSerialNumber,
    timestamp: timestamp.tstInfo.genTime,
    type: 'timestamp-authority',
  };
}

export function verifyTLogTimestamp(
  entry: TransparencyLogEntry,
  tlogAuthorities: TLogAuthority[]
): TimestampVerificationResult {
  let inclusionVerified = false;

  if (isTLogEntryWithInclusionPromise(entry)) {
    verifyTLogSET(entry, tlogAuthorities);
    inclusionVerified = true;
  }

  if (isTLogEntryWithInclusionProof(entry)) {
    verifyMerkleInclusion(entry);
    verifyCheckpoint(entry, tlogAuthorities);
    inclusionVerified = true;
  }

  if (!inclusionVerified) {
    throw new VerificationError({
      code: 'TLOG_MISSING_INCLUSION_ERROR',
      message: 'inclusion could not be verified',
    });
  }

  return {
    type: 'transparency-log',
    logID: entry.logId.keyId,
    timestamp: new Date(Number(entry.integratedTime) * 1000),
  };
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
