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
import { verifyDSSETLogBody } from './dsse';
import { verifyHashedRekordTLogBody } from './hashedrekord';
import { verifyIntotoTLogBody } from './intoto';

import type { TransparencyLogEntry } from '@sigstore/bundle';
import type { ProposedEntry } from '@sigstore/rekor-types';
import type { SignatureContent } from '../shared.types';

// Verifies that the given tlog entry matches the supplied signature content.
export function verifyTLogBody(
  entry: TransparencyLogEntry,
  sigContent: SignatureContent
): void {
  const { kind, version } = entry.kindVersion;
  const body: ProposedEntry = JSON.parse(
    entry.canonicalizedBody.toString('utf8')
  );

  if (kind !== body.kind || version !== body.apiVersion) {
    throw new VerificationError({
      code: 'TLOG_BODY_ERROR',
      message: `kind/version mismatch - expected: ${kind}/${version}, received: ${body.kind}/${body.apiVersion}`,
    });
  }

  switch (body.kind) {
    case 'dsse':
      return verifyDSSETLogBody(body, sigContent);
    case 'intoto':
      return verifyIntotoTLogBody(body, sigContent);
    case 'hashedrekord':
      return verifyHashedRekordTLogBody(body, sigContent);
    /* istanbul ignore next */
    default:
      throw new VerificationError({
        code: 'TLOG_BODY_ERROR',
        message: `unsupported kind: ${kind}`,
      });
  }
}
