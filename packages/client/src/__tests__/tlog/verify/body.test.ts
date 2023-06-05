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
import { verifyTLogBody } from '../../../tlog/verify/body';
import * as sigstore from '../../../types/sigstore';
import bundles from '../../__fixtures__/bundles';

describe('verifyTLogBody', () => {
  describe('when a message signature bundle is provided', () => {
    describe('when everything is valid', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.signature.valid.withSigningCert
      );

      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns true', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(true);
      });
    });

    describe('when the signature does NOT match the value in the tlog entry', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.signature.invalid.tlogIncorrectSigInBody
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns false', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(false);
      });
    });

    describe('when the digest does NOT match the value in the tlog entry', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.signature.invalid.tlogIncorrectDigestInBody
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns false', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(false);
      });
    });

    describe('when there is a version mismatch between the tlog entry and the body', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.signature.invalid.tlogVersionMismatch
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns false', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(false);
      });
    });
  });

  describe('when a DSSE Bundle is provided', () => {
    describe('when everything is valid', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.dsse.valid.withSigningCert
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns true', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(true);
      });
    });

    describe('when the payload hash does NOT match the value in the intoto entry', () => {
      const bundle = sigstore.bundleFromJSON(bundles.dsse.invalid.badSignature);
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns false', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(false);
      });
    });

    describe('when the signature does NOT match the value in the intoto entry', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.dsse.invalid.tlogIncorrectSigInBody
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns false', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(false);
      });
    });

    describe('when the tlog entry version is unsupported', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.dsse.invalid.tlogUnsupportedVersion
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns false', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(false);
      });
    });

    describe('when the signature count does NOT match the intoto entry', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.dsse.invalid.tlogTooManySigsInBody
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns false', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(false);
      });
    });

    describe('when there is a version mismatch between the tlog entry and the body', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.dsse.invalid.tlogVersionMismatch
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns false', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(false);
      });
    });
  });

  describe('when a DSSE Bundle w/ dsse tlog entry is provided', () => {
    describe('when everything is valid', () => {
      const bundle = sigstore.bundleFromJSON(
        bundles.dsse.valid.withDSSETLogEntry
      );
      const tlogEntry = bundle.verificationMaterial
        ?.tlogEntries[0] as sigstore.VerifiableTransparencyLogEntry;

      it('returns true', () => {
        expect(verifyTLogBody(tlogEntry, bundle.content)).toBe(true);
      });
    });
  });
});
