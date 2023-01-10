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
import fs from 'fs';
import { verifySigningCertificate } from '../../ca/verify';
import { translateLegacyBundleJSON } from '../../types';
import * as sigstore from '../../types/sigstore';
import bundles from '../__fixtures__/bundles/';

describe('verifySigningCertificate', () => {
  // Temporary until we reconsole bundle formats
  const bundleJSON = translateLegacyBundleJSON(
    bundles.dsse.valid.withSigningCert
  );
  const bundle = sigstore.Bundle.fromJSON(bundleJSON);

  const trustedRootJSON = JSON.parse(
    fs
      .readFileSync(require.resolve('../../../store/trusted_root.json'))
      .toString('utf8')
  );
  const trustedRoot: sigstore.TrustedRoot =
    sigstore.TrustedRoot.fromJSON(trustedRootJSON);

  const opts: sigstore.ArtifactVerificationOptions_CtlogOptions = {
    disable: false,
    detachedSct: false,
    threshold: 1,
  };

  describe('when the bundle does not contain a certificate chain', () => {
    // Bundle with no certificate chain
    const bundleJSON = translateLegacyBundleJSON(
      bundles.dsse.valid.withPublicKey
    );
    const bundle = sigstore.Bundle.fromJSON(bundleJSON);

    it('throws an error', () => {
      expect(() =>
        verifySigningCertificate(bundle, trustedRoot, opts)
      ).toThrowError('No certificate chain in bundle');
    });
  });

  describe('when there are NO valid CAs for the signing certificate', () => {
    // CA w/ validFor.end date in the past
    const ca: sigstore.CertificateAuthority = {
      uri: '',
      subject: undefined,
      validFor: {
        start: new Date(0),
        end: new Date(1),
      },
      certChain: { certificates: [] },
    };

    const trustedRoot: sigstore.TrustedRoot = {
      certificateAuthorities: [ca],
      ctlogs: [],
      tlogs: [],
      timestampAuthorities: [],
    };

    it('throws an error', () => {
      expect(() =>
        verifySigningCertificate(bundle, trustedRoot, opts)
      ).toThrowError('No valid certificate authorities');
    });
  });

  describe('when signing cert does NOT match the certificate authority', () => {
    // CA with no trusted cert chain (will prevent signing cert from being verified)
    const ca: sigstore.CertificateAuthority = {
      uri: '',
      subject: undefined,
      validFor: {
        start: new Date(0),
      },
      certChain: undefined,
    };

    const trustedRoot: sigstore.TrustedRoot = {
      certificateAuthorities: [ca],
      ctlogs: [],
      tlogs: [],
      timestampAuthorities: [],
    };

    it('throws an error', () => {
      expect(() =>
        verifySigningCertificate(bundle, trustedRoot, opts)
      ).toThrowError('No valid certificate chain');
    });
  });

  describe('when the SCT verification threshold is not met', () => {
    const threshold = Number.MAX_SAFE_INTEGER;

    describe('when SCT verification is disabled', () => {
      const opts: sigstore.ArtifactVerificationOptions_CtlogOptions = {
        disable: true,
        detachedSct: false,
        threshold,
      };

      it('returns without error', () => {
        expect(() =>
          verifySigningCertificate(bundle, trustedRoot, opts)
        ).not.toThrow();
      });
    });

    describe('when SCT verification is NOT disabled', () => {
      const opts: sigstore.ArtifactVerificationOptions_CtlogOptions = {
        disable: false,
        detachedSct: false,
        threshold,
      };

      it('throws an error', () => {
        expect(() =>
          verifySigningCertificate(bundle, trustedRoot, opts)
        ).toThrowError(/Not enough SCTs verified/);
      });
    });
  });

  describe('when everything verifies without error', () => {
    it('returns without error', () => {
      expect(() =>
        verifySigningCertificate(bundle, trustedRoot, opts)
      ).not.toThrow();
    });
  });
});
