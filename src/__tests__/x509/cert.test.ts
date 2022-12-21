import { pem } from '../../util';
import { x509Certificate } from '../../x509/cert';
import { certificates } from '../__fixtures__/certs';

describe('x509Certificate', () => {
  describe('.parse', () => {
    describe('when parsing a root certificate', () => {
      it('parses successfully', () => {
        const cert = x509Certificate.parse(certificates.root);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('1990-01-01T00:00:00.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2040-01-01T00:00:00.000Z');

        expect(cert.subject).toHaveLength(38);
        expect(cert.issuer).toHaveLength(38);

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

        expect(cert.extSubjectKeyID).toBeDefined();
        expect(cert.extSubjectKeyID?.oid).toBe('2.5.29.14');
        expect(cert.extSubjectKeyID?.critical).toBe(false);
        expect(cert.extSubjectKeyID?.keyIdentifier).toBeTruthy();

        expect(cert.extAuthorityKeyID).toBeUndefined();
        expect(cert.extSubjectAltName).toBeUndefined();
        expect(cert.extSCT).toBeUndefined();
      });
    });

    describe('when parsing an intermediate certificate', () => {
      it('parses successfully', () => {
        const cert = x509Certificate.parse(certificates.intermediate);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('1990-01-01T00:00:00.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2040-01-01T00:00:00.000Z');

        expect(cert.subject).toHaveLength(51);
        expect(cert.issuer).toHaveLength(38);

        expect(cert.extBasicConstraints).toBeDefined();
        expect(cert.extBasicConstraints?.critical).toBe(true);
        expect(cert.extBasicConstraints?.isCA).toBe(true);
        expect(cert.extBasicConstraints?.pathLenConstraint).toEqual(BigInt(0));

        expect(cert.extKeyUsage).toBeDefined();
        expect(cert.extKeyUsage?.critical).toBe(true);
        expect(cert.extKeyUsage?.digitalSignature).toBe(false);
        expect(cert.extKeyUsage?.keyCertSign).toBe(true);
        expect(cert.extKeyUsage?.crlSign).toBe(true);

        expect(cert.extSubjectKeyID).toBeDefined();
        expect(cert.extSubjectKeyID?.oid).toBe('2.5.29.14');
        expect(cert.extSubjectKeyID?.critical).toBe(false);
        expect(cert.extSubjectKeyID?.keyIdentifier).toBeTruthy();

        expect(cert.extAuthorityKeyID).toBeUndefined();
        expect(cert.extSubjectAltName).toBeUndefined();
        expect(cert.extSCT).toBeUndefined();
      });
    });

    describe('when parsing a leaf certificate', () => {
      it('parses successfully', () => {
        const cert = x509Certificate.parse(certificates.leaf);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('1990-01-01T00:00:00.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2040-01-01T00:00:00.000Z');

        expect(cert.subject).toHaveLength(0);
        expect(cert.issuer).toHaveLength(51);

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
        expect(cert.extSubjectAltName?.uri).toBe('http://foobar.dev');

        expect(cert.extAuthorityKeyID).toBeDefined();
        expect(cert.extAuthorityKeyID?.oid).toBe('2.5.29.35');
        expect(cert.extAuthorityKeyID?.critical).toBe(false);
        expect(cert.extAuthorityKeyID?.keyIdentifier).toBeTruthy();

        expect(cert.extSubjectKeyID).toBeDefined();
        expect(cert.extSubjectKeyID?.oid).toBe('2.5.29.14');
        expect(cert.extSubjectKeyID?.critical).toBe(false);
        expect(cert.extSubjectKeyID?.keyIdentifier).toBeTruthy();
      });
    });

    describe('when parsing a certificate with an unrecognized critical extension', () => {
      it('throws an error', () => {
        const der = pem.toDER(certificates.poisoned);
        expect(() => x509Certificate.parse(der)).toThrow();
      });
    });
  });

  describe('#isCA', () => {
    describe('when the certificate is a CA', () => {
      const cert = x509Certificate.parse(certificates.root);
      it('returns true', () => {
        expect(cert.isCA).toBe(true);
      });
    });

    describe('when the certificate is not a CA', () => {
      const cert = x509Certificate.parse(certificates.leaf);

      it('returns true', () => {
        expect(cert.isCA).toBe(false);
      });
    });
  });

  describe('#validForDate', () => {
    const cert = x509Certificate.parse(certificates.leaf);

    describe('when the date is within the validity period', () => {
      it('returns true', () => {
        expect(cert.validForDate(new Date('2000-01-01T00:00:00.000Z'))).toBe(
          true
        );
      });
    });

    describe('when the date is before the validity period', () => {
      it('returns false', () => {
        expect(cert.validForDate(new Date('1980-01-01T00:00:00.000Z'))).toBe(
          false
        );
      });
    });

    describe('when the date is after the validity period', () => {
      it('returns false', () => {
        expect(cert.validForDate(new Date('2050-01-01T00:00:00.000Z'))).toBe(
          false
        );
      });
    });
  });

  describe('#verify', () => {
    const leafCert = x509Certificate.parse(certificates.leaf);
    const intCert = x509Certificate.parse(certificates.intermediate);
    const rootCert = x509Certificate.parse(certificates.root);

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

  describe('#equals', () => {
    const leaf1Cert = x509Certificate.parse(certificates.leaf);
    const leaf2Cert = x509Certificate.parse(certificates.leaf);
    const rootCert = x509Certificate.parse(certificates.root);

    describe('when the certificates are the same object', () => {
      it('returns true', () => {
        expect(leaf1Cert.equals(leaf1Cert)).toBe(true);
      });
    });

    describe('when the certificates are equal', () => {
      it('returns true', () => {
        expect(leaf1Cert.equals(leaf2Cert)).toBe(true);
      });
    });

    describe('when the certificates are NOT equal', () => {
      it('returns false', () => {
        expect(leaf1Cert.equals(rootCert)).toBe(false);
      });
    });
  });
});
