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
import { X509Certificate } from '../../x509/cert';
import { certificates } from '../__fixtures__/certs';

describe('X509Certificate', () => {
  describe('.parse', () => {
    describe('when parsing a root certificate', () => {
      it('parses successfully', () => {
        const cert = X509Certificate.parse(certificates.root);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('1990-01-01T00:00:00.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2040-01-01T00:00:00.000Z');

        expect(cert.subject).toHaveLength(38);
        expect(cert.issuer).toHaveLength(38);

        expect(cert.publicKey).toBeDefined();

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
        const cert = X509Certificate.parse(certificates.intermediate);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('1990-01-01T00:00:00.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2040-01-01T00:00:00.000Z');

        expect(cert.subject).toHaveLength(51);
        expect(cert.issuer).toHaveLength(38);

        expect(cert.publicKey).toBeDefined();

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
        const cert = X509Certificate.parse(certificates.leaf);

        expect(cert.version).toBe('v3');
        expect(cert.notBefore).toBeInstanceOf(Date);
        expect(cert.notBefore.toISOString()).toBe('1990-01-01T00:00:00.000Z');
        expect(cert.notAfter).toBeInstanceOf(Date);
        expect(cert.notAfter.toISOString()).toBe('2040-01-01T00:00:00.000Z');

        expect(cert.subject).toHaveLength(0);
        expect(cert.issuer).toHaveLength(51);

        expect(cert.publicKey).toBeDefined();

        expect(cert.extBasicConstraints).toBeUndefined();

        expect(cert.extKeyUsage).toBeDefined();
        expect(cert.extKeyUsage?.critical).toBe(true);
        expect(cert.extKeyUsage?.digitalSignature).toBe(true);
        expect(cert.extKeyUsage?.keyCertSign).toBe(false);
        expect(cert.extKeyUsage?.crlSign).toBe(false);

        expect(cert.extSubjectAltName).toBeDefined();
        expect(cert.extSubjectAltName?.rfc822Name).toBeUndefined();
        expect(cert.extSubjectAltName?.uri).toBe('http://foobar.dev');
        expect(cert.extSubjectAltName?.otherName('1.3.6.1.4.1.57264.1.7')).toBe(
          'FOO'
        );
        expect(cert.extSubjectAltName?.otherName('9.9.9.9')).toBeUndefined();

        expect(cert.extAuthorityKeyID).toBeDefined();
        expect(cert.extAuthorityKeyID?.oid).toBe('2.5.29.35');
        expect(cert.extAuthorityKeyID?.critical).toBe(false);
        expect(cert.extAuthorityKeyID?.keyIdentifier).toBeTruthy();

        expect(cert.extSubjectKeyID).toBeDefined();
        expect(cert.extSubjectKeyID?.oid).toBe('2.5.29.14');
        expect(cert.extSubjectKeyID?.critical).toBe(false);
        expect(cert.extSubjectKeyID?.keyIdentifier).toBeTruthy();

        expect(cert.extSCT).toBeUndefined();
      });
    });
  });

  describe('#isCA', () => {
    describe('when the certificate is a CA', () => {
      const cert = X509Certificate.parse(certificates.root);
      it('returns true', () => {
        expect(cert.isCA).toBe(true);
      });
    });

    describe('when the certificate is not a CA', () => {
      const cert = X509Certificate.parse(certificates.leaf);

      it('returns true', () => {
        expect(cert.isCA).toBe(false);
      });
    });
  });

  describe('#validForDate', () => {
    const cert = X509Certificate.parse(certificates.leaf);

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

  describe('#extKeyUsage', () => {
    describe('when the certificate has key usage extensions', () => {
      const cert = X509Certificate.parse(certificates.leaf);

      it('returns the key usage extensions', () => {
        expect(cert.extKeyUsage).toBeDefined();
      });
    });

    describe('when the certificate does not have key usage extensions', () => {
      const cert = X509Certificate.parse(certificates.nokeyusage);

      it('returns undefined', () => {
        expect(cert.extKeyUsage).toBeUndefined();
      });
    });
  });

  describe('#equals', () => {
    const leaf1Cert = X509Certificate.parse(certificates.leaf);
    const leaf2Cert = X509Certificate.parse(certificates.leaf);
    const rootCert = X509Certificate.parse(certificates.root);

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

  describe('#extSCT', () => {
    describe('when the certificate has SCT extensions', () => {
      const cert = X509Certificate.parse(certificates.fulcioleaf);

      it('returns the SCT extensions', () => {
        expect(cert.extSCT).toBeDefined();
      });
    });

    describe('when the certificate does not have SCT extensions', () => {
      const cert = X509Certificate.parse(certificates.leaf);

      it('returns undefined', () => {
        expect(cert.extSCT).toBeUndefined();
      });
    });
  });

  describe('#extension', () => {
    const cert = X509Certificate.parse(certificates.leaf);

    describe('when the requested extension is present', () => {
      it('returns the extension', () => {
        const ext = cert.extension('2.5.29.17');

        expect(ext).toBeDefined();
        expect(ext?.oid).toBe('2.5.29.17');
      });
    });

    describe('when the requested extension is NOT present', () => {
      it('returns the extension', () => {
        const ext = cert.extension('9.9.9.9');
        expect(ext).toBeUndefined();
      });
    });
  });

  describe('#subjectAltName', () => {
    describe('when the certificate has subjectAltName extensions', () => {
      const cert = X509Certificate.parse(certificates.deepleaf);
      it('returns the subjectAltName extensions', () => {
        expect(cert.subjectAltName).toBe('http://foobar.dev');
      });
    });

    describe('when the certificate does not have subjectAltName extensions', () => {
      const cert = X509Certificate.parse(certificates.nosan);

      it('returns undefined', () => {
        expect(cert.subjectAltName).toBeUndefined();
      });
    });
  });

  describe('#clone', () => {
    const cert = X509Certificate.parse(certificates.leaf);

    it('returns a new certificate', () => {
      const clone = cert.clone();
      expect(clone).not.toBe(cert);
      expect(clone.equals(cert)).toBe(true);
    });
  });

  describe('#verify', () => {
    const leafCert = X509Certificate.parse(certificates.leaf);
    const intCert = X509Certificate.parse(certificates.intermediate);
    const rootCert = X509Certificate.parse(certificates.root);

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
