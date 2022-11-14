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
import {
  InvalidBundleError,
  UnsupportedVersionError,
  VerificationError,
} from '../../error';
import { verifyTLogEntries } from '../../tlog/verify';
import { bundleFromJSON } from '../../types/bundle';
import bundles, { tlogKeys } from '../__fixtures__/bundles';

describe('verifyTLogEntries', () => {
  describe('when a message signature Bundle is provided', () => {
    describe('when everything is valid', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).not.toThrow();
      });
    });

    describe('when there is no key for the logID', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, {})).toThrow(VerificationError);
      });
    });

    describe('when there is no signature in the bundle', () => {
      const bundle = bundleFromJSON(bundles.signature.invalid.setMissing);

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          InvalidBundleError
        );
      });
    });

    describe('when the SET does not match', () => {
      const bundle = bundleFromJSON(bundles.signature.invalid.setMismatch);

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          VerificationError
        );
      });
    });

    describe('when the signature does NOT match the value in the tlog entry', () => {
      const bundle = bundleFromJSON(
        bundles.signature.invalid.tlogIncorrectSigInBody
      );

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          VerificationError
        );
      });
    });

    describe('when there is a version mismatch between the tlog entry and the body', () => {
      const bundle = bundleFromJSON(
        bundles.signature.invalid.tlogVersionMismatch
      );

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          VerificationError
        );
      });
    });
  });

  describe('when a DSSE Bundle is provided', () => {
    describe('when everything is valid', () => {
      const bundle = bundleFromJSON(bundles.dsse.valid.withSigningCert);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).not.toThrow();
      });
    });

    describe('when the SET does not match', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogSETMismatch);

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          VerificationError
        );
      });
    });

    describe('when there is no log ID in the tlog entry', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogLogIDMissing);

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          InvalidBundleError
        );
      });
    });

    describe('when the kindVersion info is missing from the tlog entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogKindVersionMissing
      );

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          InvalidBundleError
        );
      });
    });
    describe('when the payload hash does NOT match the value in the intoto entry', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.badSignature);

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          VerificationError
        );
      });
    });

    describe('when the signature does NOT match the value in the intoto entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogIncorrectSigInBody
      );

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          VerificationError
        );
      });
    });

    describe('when the tlog entry version is unsupported', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogUnsupportedVersion
      );

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          UnsupportedVersionError
        );
      });
    });

    describe('when the signature count does NOT match the intoto entry', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogTooManySigsInBody);

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          VerificationError
        );
      });
    });

    describe('when there is a version mismatch between the tlog entry and the body', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogVersionMismatch);

      it('throws an error', () => {
        expect(() => verifyTLogEntries(bundle, tlogKeys)).toThrow(
          VerificationError
        );
      });
    });
  });
});
