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
import type { CertAuthority, TLogAuthority } from './trust.types';

export function filterCertAuthorities(
  certAuthorities: CertAuthority[],
  timestamp: Date
): CertAuthority[] {
  return certAuthorities.filter((ca) => {
    return ca.validFor.start <= timestamp && ca.validFor.end >= timestamp;
  });
}

type TLogAuthorityFilterCriteria = {
  targetDate: Date;
  logID?: Buffer;
};

// Filter the list of tlog instances to only those which match the given log
// ID and have public keys which are valid for the given integrated time.
export function filterTLogAuthorities(
  tlogAuthorities: TLogAuthority[],
  criteria: TLogAuthorityFilterCriteria
): TLogAuthority[] {
  return tlogAuthorities.filter((tlog) => {
    // If we're filtering by log ID and the log IDs don't match, we can't use
    // this tlog
    if (criteria.logID && !tlog.logID.equals(criteria.logID)) {
      return false;
    }

    // Check that the integrated time is within the validFor range
    return (
      tlog.validFor.start <= criteria.targetDate &&
      criteria.targetDate <= tlog.validFor.end
    );
  });
}
