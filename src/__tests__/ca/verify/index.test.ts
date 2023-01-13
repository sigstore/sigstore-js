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
import fs from 'fs';
import { verifySigningCertificate } from '../../../ca/verify';
import * as sigstore from '../../../types/sigstore';
import bundles from '../../__fixtures__/bundles/';

describe('verifySigningCertificate', () => {
  // Temporary until we reconsole bundle formats
  const bundleJSON = bundles.dsse.valid.withSigningCert;
  const bundle = sigstore.Bundle.fromJSON(
    bundleJSON
  ) as sigstore.BundleWithCertificateChain;

  const trustedRootJSON = JSON.parse(
    fs
      .readFileSync(require.resolve('../../../../store/trusted_root.json'))
      .toString('utf8')
  );
  const trustedRoot: sigstore.TrustedRoot =
    sigstore.TrustedRoot.fromJSON(trustedRootJSON);

  const ctlogOptions: sigstore.ArtifactVerificationOptions_CtlogOptions = {
    disable: false,
    detachedSct: false,
    threshold: 1,
  };

  const signers: sigstore.CAArtifactVerificationOptions['signers'] = {
    $case: 'certificateIdentities',
    certificateIdentities: {
      identities: [
        {
          issuer: 'https://github.com/login/oauth',
          san: {
            type: sigstore.SubjectAlternativeNameType.EMAIL,
            identity: {
              $case: 'value',
              value: Buffer.from('YnJpYW5AZGVoYW1lci5jb20=', 'base64').toString(
                'utf-8'
              ),
            },
          },
          oids: [],
        },
      ],
    },
  };

  const opts: sigstore.CAArtifactVerificationOptions = {
    ctlogOptions,
    signers,
  };

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
      mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
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
      mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
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
      const ctlogOptions: sigstore.ArtifactVerificationOptions_CtlogOptions = {
        disable: true,
        detachedSct: false,
        threshold,
      };

      const opts = {
        ctlogOptions,
        signers,
      };

      it('returns without error', () => {
        expect(() =>
          verifySigningCertificate(bundle, trustedRoot, opts)
        ).not.toThrow();
      });
    });

    describe('when SCT verification is NOT disabled', () => {
      const ctlogOptions: sigstore.ArtifactVerificationOptions_CtlogOptions = {
        disable: false,
        detachedSct: false,
        threshold,
      };

      it('throws an error', () => {
        expect(() =>
          verifySigningCertificate(bundle, trustedRoot, {
            ctlogOptions,
            signers,
          })
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
