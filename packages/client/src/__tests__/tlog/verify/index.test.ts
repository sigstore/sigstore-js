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
import { VerificationError } from '../../../error';
import { verifyTLogEntries } from '../../../tlog/verify/index';
import * as sigstore from '../../../types/sigstore';
import bundles from '../../__fixtures__/bundles';
import { trustedRoot } from '../../__fixtures__/trust';

describe('verifyTLogEntries', () => {
  const bundle = sigstore.bundleFromJSON(
    bundles.signature.valid.withSigningCert
  );

  const options: sigstore.ArtifactVerificationOptions_TlogOptions = {
    disable: false,
    performOnlineVerification: false,
    threshold: 1,
  };

  describe('when everything is valid', () => {
    describe('when the bundle has a signing certificate', () => {
      it('does NOT throw an error', () => {
        expect(() =>
          verifyTLogEntries(bundle, trustedRoot, options)
        ).not.toThrow();
      });
    });

    describe('when the bundle does NOT have a signing certificate', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.signature.valid.withPublicKey
      );

      it('does NOT throw an error', () => {
        expect(() =>
          verifyTLogEntries(bundle, trustedRoot, options)
        ).not.toThrow();
      });
    });
  });

  describe('when the verification threshold is not met', () => {
    const options: sigstore.ArtifactVerificationOptions_TlogOptions = {
      disable: false,
      performOnlineVerification: false,
      threshold: Number.MAX_SAFE_INTEGER,
    };

    it('throws an error', () => {
      expect(() => verifyTLogEntries(bundle, trustedRoot, options)).toThrow(
        VerificationError
      );
    });
  });

  describe('when online verification is requested', () => {
    const options: sigstore.ArtifactVerificationOptions_TlogOptions = {
      disable: false,
      performOnlineVerification: true,
      threshold: 1,
    };

    it('throws an error', () => {
      expect(() => verifyTLogEntries(bundle, trustedRoot, options)).toThrow(
        VerificationError
      );
    });
  });

  describe('when tlog entries are missing data necessary for verification', () => {
    const bundle = sigstore.bundleFromJSON(
      bundles.dsse.invalid.tlogKindVersionMissing
    );

    it('throws an error', () => {
      expect(() => verifyTLogEntries(bundle, trustedRoot, options)).toThrow(
        VerificationError
      );
    });
  });
});
