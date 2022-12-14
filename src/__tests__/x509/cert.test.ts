import { pem } from '../../util';
import { x509Certificate } from '../../x509/cert';
import { certificates } from '../__fixtures__/certs';

describe('x509Certificate', () => {
  describe('parsing', () => {
    describe('when parsing a root certificate', () => {
      const derCert = pem.toDER(certificates.root);

      it('parses a certificate', () => {
        const cert = x509Certificate.fromDER(derCert);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('2021-10-07T13:56:59.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2031-10-05T13:56:58.000Z');

        expect(cert.subject).toHaveLength(42);
        expect(cert.issuer).toHaveLength(42);

        expect(cert.extBasicConstraints).toBeDefined();
        expect(cert.extBasicConstraints?.oid).toBe('2.5.29.19');
        expect(cert.extBasicConstraints?.critical).toBe(true);
        expect(cert.extBasicConstraints?.isCA).toBe(true);
        expect(cert.extBasicConstraints?.pathLenConstraint).toBeUndefined();

        expect(cert.extKeyUsage).toBeDefined();
        expect(cert.extKeyUsage?.oid).toBe('2.5.29.15');
        expect(cert.extKeyUsage?.critical).toBe(true);
        expect(cert.extKeyUsage?.digitalSignature).toBe(false);
        expect(cert.extKeyUsage?.keyCertSign).toBe(true);
        expect(cert.extKeyUsage?.crlSign).toBe(true);
      });
    });

    describe('when parsing an intermediate certificate', () => {
      const derCert = pem.toDER(certificates.intermediate);

      it('parses a certificate', () => {
        const cert = x509Certificate.fromDER(derCert);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('2022-04-13T20:06:15.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2031-10-05T13:56:58.000Z');

        expect(cert.subject).toHaveLength(55);
        expect(cert.issuer).toHaveLength(42);

        expect(cert.extBasicConstraints).toBeDefined();
        expect(cert.extBasicConstraints?.critical).toBe(true);
        expect(cert.extBasicConstraints?.isCA).toBe(true);
        expect(cert.extBasicConstraints?.pathLenConstraint).toEqual(BigInt(0));

        expect(cert.extKeyUsage).toBeDefined();
        expect(cert.extKeyUsage?.critical).toBe(true);
        expect(cert.extKeyUsage?.digitalSignature).toBe(false);
        expect(cert.extKeyUsage?.keyCertSign).toBe(true);
        expect(cert.extKeyUsage?.crlSign).toBe(true);
      });
    });

    describe('when parsing a leaf certificate', () => {
      const derCert = pem.toDER(certificates.leaf);
      it('parses a certificate', () => {
        const cert = x509Certificate.fromDER(derCert);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('2022-12-08T16:18:39.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2022-12-08T16:28:39.000Z');

        expect(cert.subject).toHaveLength(0);
        expect(cert.issuer).toHaveLength(55);

        expect(cert.publicKey).toBeDefined();
        expect(cert.publicKey.type).toBe('public');
        expect(cert.publicKey.asymmetricKeyType).toBe('ec');

        expect(cert.extBasicConstraints).toBeUndefined();

        expect(cert.extKeyUsage).toBeDefined();
        expect(cert.extKeyUsage?.critical).toBe(true);
        expect(cert.extKeyUsage?.digitalSignature).toBe(true);
        expect(cert.extKeyUsage?.keyCertSign).toBe(false);
        expect(cert.extKeyUsage?.crlSign).toBe(false);

        expect(cert.extSubjectAltName).toBeDefined();
        expect(cert.extSubjectAltName?.rfc822Name).toBeUndefined();
        expect(cert.extSubjectAltName?.uri).toBe(
          'https://github.com/sigstore/sigstore-js/.github/workflows/publish.yml@refs/tags/v0.2.0'
        );

        expect(cert.extSCT).toBeDefined();
        expect(cert.extSCT?.critical).toBe(false);
      });
    });
  });

  describe('#verify', () => {
    const leafCert = x509Certificate.fromDER(pem.toDER(certificates.leaf));
    const intCert = x509Certificate.fromDER(
      pem.toDER(certificates.intermediate)
    );
    const rootCert = x509Certificate.fromDER(pem.toDER(certificates.root));

    describe('when the issuer is provided', () => {
      describe('when the issuer is a parent certificate', () => {
        it('returns true', () => {
          expect(leafCert.verify(intCert)).toBe(true);
          expect(intCert.verify(rootCert)).toBe(true);
        });
      });

      describe('when the issuer is NOT a parent', () => {
        it('returns false', () => {
          expect(leafCert.verify(rootCert)).toBe(false);
          expect(intCert.verify(leafCert)).toBe(false);
          expect(rootCert.verify(leafCert)).toBe(false);
          expect(rootCert.verify(intCert)).toBe(false);
        });
      });
    });

    describe('when the issuer is NOT provided', () => {
      describe('when the certificate is self-signed', () => {
        it('returns true', () => {
          expect(rootCert.verify()).toBe(true);
        });
      });

      describe('when the certificate is NOT self-signed', () => {
        it('returns false', () => {
          expect(intCert.verify()).toBe(false);
          expect(leafCert.verify()).toBe(false);
        });
      });
    });
  });
});
