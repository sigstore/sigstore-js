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
import { bundleFromJSON } from '@sigstore/bundle';
import { signatureContent } from '../../bundle';
import { VerificationError } from '../../error';
import { verifyTLogBody } from '../../tlog';
import * as bundles from '../__fixtures__/bundles';

describe('verifyTLogBody', () => {
  describe('when the tlog entry matches (hashedrekord)', () => {
    const bundle = bundleFromJSON(
      bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
    );
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const content = signatureContent(bundle);

    it('does NOT throw an error', () => {
      expect(verifyTLogBody(tlogEntry, content)).toBeUndefined();
    });
  });

  describe('when the tlog entry matches (intoto)', () => {
    const bundle = bundleFromJSON(
      bundles.V1.DSSE.WITH_SIGNING_CERT.TLOG_INTOTO
    );
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const content = signatureContent(bundle);

    it('does NOT throw an error', () => {
      expect(verifyTLogBody(tlogEntry, content)).toBeUndefined();
    });
  });

  describe('when the tlog entry matches (dsse)', () => {
    const bundle = bundleFromJSON(bundles.V1.DSSE.WITH_SIGNING_CERT.TLOG_DSSE);
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const content = signatureContent(bundle);

    it('does NOT throw an error', () => {
      expect(verifyTLogBody(tlogEntry, content)).toBeUndefined();
    });
  });

  describe('when there is a version mismatch between the tlog entry and the body', () => {
    const bundle = bundleFromJSON(bundles.V1.DSSE.WITH_SIGNING_CERT.TLOG_DSSE);
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const content = signatureContent(bundle);

    beforeEach(() => {
      tlogEntry.kindVersion.version = '0.0.X';
    });

    it('throws an error', () => {
      expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
        VerificationError,
        'TLOG_BODY_ERROR'
      );
    });
  });
});
