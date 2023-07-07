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
import { verifyTLogSET } from '../../../tlog/verify/set';
import * as sigstore from '../../../types/sigstore';
import { crypto } from '../../../util';
import bundles from '../../__fixtures__/bundles';

describe('verifyTLogSET', () => {
  const keyBytes = Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    'base64'
  );
  const keyID = crypto.hash(keyBytes);

  const publicKey: sigstore.PublicKey = {
    rawBytes: keyBytes,
    keyDetails: sigstore.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
  };

  const validTLog: sigstore.TransparencyLogInstance = {
    baseUrl: 'https://tlog.sigstore.dev',
    hashAlgorithm: sigstore.HashAlgorithm.SHA2_256,
    publicKey,
    logId: { keyId: keyID },
  };

  const invalidTLog: sigstore.TransparencyLogInstance = {
    hashAlgorithm: sigstore.HashAlgorithm.SHA2_256,
    baseUrl: 'https://invalid.tlog.example.com',
    logId: { keyId: Buffer.from('invalid') },
    publicKey: {
      keyDetails: sigstore.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
      rawBytes: Buffer.from('invalid'),
    },
  };

  const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
  const entry = bundle.verificationMaterial
    ?.tlogEntries[0] as TLogEntryWithInclusionPromise;

  describe('when there is a matching TLogInstance', () => {
    const tlogs = [invalidTLog, validTLog];

    describe('when the SET can be verified', () => {
      it('returns true', () => {
        expect(verifyTLogSET(entry, tlogs)).toBe(true);
      });
    });

    describe('when the SET can NOT be verified', () => {
      const bundle = bundleFromJSON(bundles.signature.invalid.setMismatch);
      const entry = bundle.verificationMaterial
        ?.tlogEntries[0] as TLogEntryWithInclusionPromise;

      it('returns false', () => {
        expect(verifyTLogSET(entry, tlogs)).toBe(false);
      });
    });

    describe('when the matching TLogInstance has no public key', () => {
      const tlogs = [
        {
          ...validTLog,
          publicKey: undefined,
        },
      ];

      it('returns false', () => {
        expect(verifyTLogSET(entry, tlogs)).toBe(false);
      });
    });

    describe('when the matching TLogInstance has an empty public key', () => {
      const tlogs = [
        {
          ...validTLog,
          publicKey: { ...publicKey, rawBytes: undefined },
        },
      ];

      it('returns false', () => {
        expect(verifyTLogSET(entry, tlogs)).toBe(false);
      });
    });

    describe('when the public key for the matching TLogInstance is not valid', () => {
      describe('when public key has has no key', () => {
        const tlogs: sigstore.TransparencyLogInstance[] = [
          {
            ...validTLog,
            publicKey: {
              rawBytes: undefined,
              keyDetails: sigstore.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
              validFor: { start: undefined },
            },
          },
        ];

        it('returns false', () => {
          expect(verifyTLogSET(entry, tlogs)).toBe(false);
        });
      });

      describe('when public key has no start', () => {
        const tlogs: sigstore.TransparencyLogInstance[] = [
          {
            ...validTLog,
            publicKey: {
              ...publicKey,
              validFor: { start: undefined },
            },
          },
        ];

        it('returns false', () => {
          expect(verifyTLogSET(entry, tlogs)).toBe(false);
        });
      });

      describe('when the public key has a start after the integrated time', () => {
        const tlogs = [
          {
            ...validTLog,
            publicKey: {
              ...publicKey,
              validFor: { start: new Date(Number.MIN_SAFE_INTEGER) },
            },
          },
        ];

        it('returns false', () => {
          expect(verifyTLogSET(entry, tlogs)).toBe(false);
        });
      });

      describe('when the public key has an end before the integrated time', () => {
        const tlogs = [
          {
            ...validTLog,
            publicKey: {
              ...publicKey,
              validFor: { start: new Date(0), end: new Date(0) },
            },
          },
        ];

        it('returns false', () => {
          expect(verifyTLogSET(entry, tlogs)).toBe(false);
        });
      });
    });
  });

  describe('when there is NO matching TLogInstance', () => {
    const tlogs = [invalidTLog];

    it('returns false', () => {
      expect(verifyTLogSET(entry, tlogs)).toBe(false);
    });
  });
});
