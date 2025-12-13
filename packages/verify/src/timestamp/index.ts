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
import { RFC3161Timestamp } from '@sigstore/core';
import { verifyRFC3161Timestamp } from './tsa';

import type { TransparencyLogEntry } from '@sigstore/bundle';
import type { CertAuthority } from '../trust';

export type TimestampType = 'transparency-log' | 'timestamp-authority';

export type TimestampVerificationResult = {
  type: TimestampType;
  logID: Buffer;
  timestamp: Date;
};

export function getTSATimestamp(
  timestamp: RFC3161Timestamp,
  data: Buffer,
  timestampAuthorities: CertAuthority[]
): TimestampVerificationResult {
  verifyRFC3161Timestamp(timestamp, data, timestampAuthorities);

  return {
    type: 'timestamp-authority',
    logID: timestamp.signerSerialNumber,
    timestamp: timestamp.signingTime,
  };
}

export function getTLogTimestamp(
  entry: TransparencyLogEntry
): TimestampVerificationResult {
  return {
    type: 'transparency-log',
    logID: entry.logId.keyId,
    timestamp: new Date(Number(entry.integratedTime) * 1000),
  };
}
