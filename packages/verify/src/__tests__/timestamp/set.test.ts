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
import {
  bundleFromJSON,
  TLogEntryWithInclusionPromise,
} from '@sigstore/bundle';
import { crypto } from '@sigstore/core';
import { fromPartial } from '@total-typescript/shoehorn';
import { VerificationError } from '../../error';
import { verifyTLogSET } from '../../timestamp/set';
import bundles from '../__fixtures__/bundles/v01';

import type { TLogAuthority } from '../../trust';

describe('verifyTLogSET', () => {
  const keyBytes = Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    'base64'
  );
  const keyID = crypto.hash(keyBytes);

  const validTLog: TLogAuthority = {
    logID: keyID,
    publicKey: crypto.createPublicKey(keyBytes),
    validFor: { start: new Date(0), end: new Date('2100-01-01') },
  };

  const invalidTLog: TLogAuthority = {
    logID: Buffer.from('invalid'),
    publicKey: crypto.createPublicKey(keyBytes),
    validFor: { start: new Date(0), end: new Date('2100-01-01') },
  };

  const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
  const entry: TLogEntryWithInclusionPromise = fromPartial(
    bundle.verificationMaterial?.tlogEntries[0]
  );

  describe('when there is a matching TLogInstance', () => {
    const tlogs = [invalidTLog, validTLog];

    describe('when the SET can be verified', () => {
      it('does NOT throw an error', () => {
        expect(verifyTLogSET(entry, tlogs)).toBeUndefined();
      });
    });

    describe('when the SET can NOT be verified', () => {
      const bundle = bundleFromJSON(bundles.signature.invalid.setMismatch);
      const entry = bundle.verificationMaterial
        ?.tlogEntries[0] as TLogEntryWithInclusionPromise;

      it('throws an error', () => {
        expect(() => verifyTLogSET(entry, tlogs)).toThrowWithCode(
          VerificationError,
          'TLOG_INCLUSION_PROMISE_ERROR'
        );
      });
    });

    describe('when the public key for the matching TLogInstance is not valid', () => {
      describe('when the public key has a start after the integrated time', () => {
        const tlogs = [
          {
            ...validTLog,
            validFor: { start: new Date(), end: new Date('2999-01-01') },
          },
        ];

        it('throws an error', () => {
          expect(() => verifyTLogSET(entry, tlogs)).toThrowWithCode(
            VerificationError,
            'TLOG_INCLUSION_PROMISE_ERROR'
          );
        });
      });

      describe('when the public key has an end before the integrated time', () => {
        const tlogs = [
          {
            ...validTLog,
            validFor: { start: new Date(0), end: new Date(0) },
          },
        ];

        it('throws an error', () => {
          expect(() => verifyTLogSET(entry, tlogs)).toThrowWithCode(
            VerificationError,
            'TLOG_INCLUSION_PROMISE_ERROR'
          );
        });
      });
    });
  });

  describe('when there is NO matching TLogInstance', () => {
    const tlogs = [invalidTLog];

    it('throws an error', () => {
      expect(() => verifyTLogSET(entry, tlogs)).toThrowWithCode(
        VerificationError,
        'TLOG_INCLUSION_PROMISE_ERROR'
      );
    });
  });
});
