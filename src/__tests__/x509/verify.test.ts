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
import { x509Certificate } from '../../x509/cert';
import { verifyCertificateChain } from '../../x509/verify';
import { certificates } from '../__fixtures__/certs';

describe('CertificateChainVerifier', () => {
  const rootCert = x509Certificate.parse(certificates.root);
  const intCert = x509Certificate.parse(certificates.intermediate);
  const leafCert = x509Certificate.parse(certificates.leaf);
  const invalidLeafCert = x509Certificate.parse(certificates.invalidleaf);

  describe('#verify', () => {
    describe('when no path contains a trusted cert', () => {
      const opts = {
        trustedCerts: [],
        untrustedCert: rootCert,
      };

      it('throws an error', () => {
        expect(() => verifyCertificateChain(opts)).toThrowError(
          'No trusted certificate path found'
        );
      });
    });

    describe('when the certificate issuer cannot be located', () => {
      const opts = {
        trustedCerts: [],
        untrustedCert: leafCert,
      };

      it('throws an error', () => {
        expect(() => verifyCertificateChain(opts)).toThrowError(
          'No valid certificate path found'
        );
      });
    });

    describe('when the validAt is outside the validity period of the cert chain', () => {
      const opts = {
        trustedCerts: [rootCert, intCert],
        untrustedCert: leafCert,
        validAt: new Date('1980-12-21T16:22:00.000Z'),
      };

      it('throws an error', () => {
        expect(() => verifyCertificateChain(opts)).toThrowError(
          'Certificate is not valid or expired at the specified date'
        );
      });
    });

    describe('when a non-CA cert is used to sign the leaf', () => {
      it('throws an error', () => {
        const opts = {
          trustedCerts: [leafCert, intCert, rootCert],
          untrustedCert: invalidLeafCert,
        };

        expect(() => verifyCertificateChain(opts)).toThrowError(
          'Intermediate certificate is not a CA'
        );
      });
    });

    describe('when the cert chain is valid', () => {
      const opts = {
        trustedCerts: [intCert, rootCert],
        untrustedCert: leafCert,
        validAt: new Date('2022-12-21T16:22:00.000Z'),
      };

      it('does not throw an error', () => {
        expect(() => verifyCertificateChain(opts)).not.toThrowError();
      });

      it('returns the trusted chain', () => {
        const trustedChain = verifyCertificateChain(opts);
        expect(trustedChain).toBeDefined();
        expect(trustedChain).toHaveLength(4);

        // The first cert in the chain is the leaf cert
        expect(trustedChain[0]).toEqual(opts.untrustedCert);
      });
    });

    describe('when the certificate chain contains a single valid cert', () => {
      const opts = {
        trustedCerts: [rootCert],
        untrustedCert: rootCert,
      };

      it('does not throw an error', () => {
        expect(() => verifyCertificateChain(opts)).not.toThrowError();
      });

      it('returns the trusted chain', () => {
        const trustedChain = verifyCertificateChain(opts);
        expect(trustedChain).toBeDefined();
        expect(trustedChain).toHaveLength(2);
        expect(trustedChain[0]).toEqual(opts.untrustedCert);
      });
    });
  });
});
