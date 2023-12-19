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
import { verifyHashedRekordTLogBody } from '../../tlog/hashedrekord';
import * as bundles from '../__fixtures__/bundles';

import type { ProposedHashedRekordEntry } from '@sigstore/rekor-types';

describe('verifyHashedRekordTLogBody', () => {
  describe('when everything is valid', () => {
    const bundle = bundleFromJSON(
      bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
    );
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const body: ProposedHashedRekordEntry = JSON.parse(
      tlogEntry.canonicalizedBody.toString('utf8')
    );
    const content = signatureContent(bundle);

    it('does NOT throw an error', () => {
      expect(verifyHashedRekordTLogBody(body, content)).toBeUndefined();
    });
  });

  describe('when the apiVersion is unsupported', () => {
    const bundle = bundleFromJSON(
      bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
    );
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const body: ProposedHashedRekordEntry = JSON.parse(
      tlogEntry.canonicalizedBody.toString('utf8')
    );
    const content = signatureContent(bundle);

    beforeEach(() => {
      /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
      (body as any).apiVersion = '0.0.0';
    });

    it('throws an error', () => {
      expect(() => verifyHashedRekordTLogBody(body, content)).toThrowWithCode(
        VerificationError,
        'TLOG_BODY_ERROR'
      );
    });
  });

  describe('when the tlog entry body is missing the signature', () => {
    const bundle = bundleFromJSON(
      bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
    );
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const body: ProposedHashedRekordEntry = JSON.parse(
      tlogEntry.canonicalizedBody.toString('utf8')
    );
    const content = signatureContent(bundle);

    beforeEach(() => {
      body.spec.signature.content = undefined;
    });

    it('throws an error', () => {
      expect(() => verifyHashedRekordTLogBody(body, content)).toThrowWithCode(
        VerificationError,
        'TLOG_BODY_ERROR'
      );
    });
  });

  describe('when the tlog entry body is missing the hash', () => {
    const bundle = bundleFromJSON(
      bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
    );
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const body: ProposedHashedRekordEntry = JSON.parse(
      tlogEntry.canonicalizedBody.toString('utf8')
    );
    const content = signatureContent(bundle);

    beforeEach(() => {
      body.spec.data.hash = undefined;
    });

    it('throws an error', () => {
      expect(() => verifyHashedRekordTLogBody(body, content)).toThrowWithCode(
        VerificationError,
        'TLOG_BODY_ERROR'
      );
    });
  });

  describe('when the signature does NOT match the value in the tlog entry', () => {
    const bundle = bundleFromJSON(
      bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
    );
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const body: ProposedHashedRekordEntry = JSON.parse(
      tlogEntry.canonicalizedBody.toString('utf8')
    );
    const content = signatureContent(bundle);

    beforeEach(() => {
      body.spec.signature.content = Buffer.from('oops').toString('base64');
    });

    it('throws an error', () => {
      expect(() => verifyHashedRekordTLogBody(body, content)).toThrowWithCode(
        VerificationError,
        'TLOG_BODY_ERROR'
      );
    });
  });

  describe('when the digest does NOT match the value in the tlog entry', () => {
    const bundle = bundleFromJSON(
      bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
    );
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const body: ProposedHashedRekordEntry = JSON.parse(
      tlogEntry.canonicalizedBody.toString('utf8')
    );
    const content = signatureContent(bundle);

    beforeEach(() => {
      body.spec.data.hash!.value = Buffer.from('oops').toString('base64');
    });

    it('throws an error', () => {
      expect(() => verifyHashedRekordTLogBody(body, content)).toThrowWithCode(
        VerificationError,
        'TLOG_BODY_ERROR'
      );
    });
  });
});
