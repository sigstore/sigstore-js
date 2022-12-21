import { x509Certificate } from '../../x509/cert';
import { verifyCertificateChain } from '../../x509/verify';
import { certificates } from '../__fixtures__/certs';

describe('CertificateChainVerifier', () => {
  const rootCert = x509Certificate.parse(certificates.root);
  const intCert = x509Certificate.parse(certificates.intermediate);
  const leafCert = x509Certificate.parse(certificates.leaf);
  const invalidLeafCert = x509Certificate.parse(certificates.invalidleaf);

  describe('#verify', () => {
    describe('when no certificates are provided', () => {
      const opts = {
        trustedCerts: [],
        certs: [],
      };

      it('throws an error', () => {
        expect(() => verifyCertificateChain(opts)).toThrowError(
          'No certificates provided'
        );
      });
    });

    describe('when no path contains a trusted cert', () => {
      const opts = {
        trustedCerts: [],
        certs: [rootCert],
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
        certs: [leafCert],
      };

      it('throws an error', () => {
        expect(() => verifyCertificateChain(opts)).toThrowError(
          'No valid certificate path found'
        );
      });
    });

    describe('when the check-date is outside the validity period of the cert chain', () => {
      const opts = {
        trustedCerts: [rootCert, intCert],
        certs: [leafCert],
        checkDate: new Date('1980-12-21T16:22:00.000Z'),
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
          trustedCerts: [intCert, rootCert],
          certs: [rootCert, intCert, leafCert, invalidLeafCert],
        };

        expect(() => verifyCertificateChain(opts)).toThrowError(
          'Intermediate certificate is not a CA'
        );
      });
    });

    describe('when the cert chain is valid', () => {
      const opts = {
        trustedCerts: [intCert, rootCert],
        certs: [rootCert, intCert, leafCert],
        checkDate: new Date('2022-12-21T16:22:00.000Z'),
      };

      it('returns without error', () => {
        verifyCertificateChain(opts);
      });
    });

    describe('when the certificate chain contains a single valid cert', () => {
      const opts = {
        trustedCerts: [rootCert],
        certs: [rootCert],
      };

      it('returns without error', () => {
        verifyCertificateChain(opts);
      });
    });
  });
});
