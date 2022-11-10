/*
Copyright 2022 The Sigstore Authors.

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
import crypto from 'crypto';
import { verifyTLogBodies, verifyTLogSET } from '../../tlog/verify';
import { bundleFromJSON } from '../../types/bundle';
import bundles from '../__fixtures__/bundles';

describe('verifyTLogSET', () => {
  const tlogKey = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`);
  const tlogKeyID = crypto
    .createHash('sha256')
    .update(tlogKey.export({ format: 'der', type: 'spki' }))
    .digest()
    .toString('hex');

  const tlogKeys = { [tlogKeyID]: tlogKey };

  describe('when a message signature Bundle is provided', () => {
    describe('when the SET is valid', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogSET(bundle, tlogKeys)).not.toThrow();
      });
    });

    describe('when there is no key for the logID', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, {})).toThrow(
          /no key found for logID/
        );
      });
    });

    describe('when there is no signature in the bundle', () => {
      const bundle = bundleFromJSON(bundles.signature.invalid.setMissing);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, tlogKeys)).toThrow(
          /no SET found in bundle/
        );
      });
    });

    describe('when the SET does not match', () => {
      const bundle = bundleFromJSON(bundles.signature.invalid.setMismatch);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, tlogKeys)).toThrow(
          /transparency log SET verification failed/
        );
      });
    });
  });

  describe('when a DSSE Bundle is provided', () => {
    describe('when the SET is valid', () => {
      const bundle = bundleFromJSON(bundles.dsse.valid.withSigningCert);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogSET(bundle, tlogKeys)).not.toThrow();
      });
    });

    describe('when the SET does not match', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogSETMismatch);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, tlogKeys)).toThrow(
          /transparency log SET verification failed/
        );
      });
    });

    describe('when there is no log ID in the tlog entry', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogLogIDMissing);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, tlogKeys)).toThrow(
          /no logId found in bundle/
        );
      });
    });
  });
});

describe('verifyTLogBodies', () => {
  describe('when a message signature Bundle is provided', () => {
    describe('when the bundle is valid', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogBodies(bundle)).not.toThrow();
      });
    });

    describe('when the signature does NOT match the value in the tlog entry', () => {
      const bundle = bundleFromJSON(
        bundles.signature.invalid.tlogIncorrectSigInBody
      );

      it('throws an error', () => {
        expect(() => verifyTLogBodies(bundle)).toThrow(
          /bundle content and tlog entry do not match/
        );
      });
    });

    describe('when there is a version mismatch between the tlog entry and the body', () => {
      const bundle = bundleFromJSON(
        bundles.signature.invalid.tlogVersionMismatch
      );

      it('throws an error', () => {
        expect(() => verifyTLogBodies(bundle)).toThrow(
          /bundle content and tlog entry do not match/
        );
      });
    });
  });

  describe('when a DSSE Bundle is provided', () => {
    describe('when the bundle is valid', () => {
      const bundle = bundleFromJSON(bundles.dsse.valid);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogBodies(bundle)).not.toThrow();
      });
    });

    describe('when the kindVersion info is missing from the tlog entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogKindVersionMissing
      );

      it('throws an error', () => {
        expect(() => verifyTLogBodies(bundle)).toThrow(
          /no kindVersion found in bundle/
        );
      });
    });
    describe('when the payload hash does NOT match the value in the intoto entry', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.badSignature);

      it('throws an error', () => {
        expect(() => verifyTLogBodies(bundle)).toThrow(
          /bundle content and tlog entry do not match/
        );
      });
    });

    describe('when the signature does NOT match the value in the intoto entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogIncorrectSigInBody
      );

      it('throws an error', () => {
        expect(() => verifyTLogBodies(bundle)).toThrow(
          /bundle content and tlog entry do not match/
        );
      });
    });

    describe('when the signature count does NOT match the intoto entry', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogTooManySigsInBody);

      it('throws an error', () => {
        expect(() => verifyTLogBodies(bundle)).toThrow(
          /bundle content and tlog entry do not match/
        );
      });
    });

    describe('when there is a version mismatch between the tlog entry and the body', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogVersionMismatch);

      it('throws an error', () => {
        expect(() => verifyTLogBodies(bundle)).toThrow(
          /bundle content and tlog entry do not match/
        );
      });
    });
  });
});
