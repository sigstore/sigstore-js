import * as sigstore from '../../types/sigstore';
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
        const cert = x509Certificate.parse(certificates.intermediate);

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
        const cert = x509Certificate.parse(certificates.leaf);

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

  describe('#extKeyUsage', () => {
    describe('when the certificate has key usage extensions', () => {
      const cert = x509Certificate.parse(certificates.leaf);

      it('returns the key usage extensions', () => {
        expect(cert.extKeyUsage).toBeDefined();
      });
    });

    describe('when the certificate does not have key usage extensions', () => {
      const cert = x509Certificate.parse(certificates.nokeyusage);

      it('returns undefined', () => {
        expect(cert.extKeyUsage).toBeUndefined();
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

  describe('#verivySCTs', () => {
    // Fulcio ctfe key
    const ctfe =
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==';

    const ctl = {
      baseUrl: '',
      hashAlgorithm: 'SHA2_256',
      publicKey: {
        rawBytes: ctfe,
        keyDetails: 'PKIX_ECDSA_P256_SHA_256',
      },
      logId: { keyId: 'CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I=' },
    };

    const logs: sigstore.TransparencyLogInstance[] = [
      sigstore.TransparencyLogInstance.fromJSON(ctl),
    ];

    describe('when the certificate does NOT have an SCT extension', () => {
      const subject = x509Certificate.parse(certificates.leaf);
      const issuer = x509Certificate.parse(certificates.intermediate);

      it('throws an error', () => {
        expect(() => {
          subject.verifySCTs(issuer, logs);
        }).toThrow(/does not contain SCT/);
      });
    });

    describe('when the certificate has an SCT extension', () => {
      // Fulcio-issued certificate with an SCT extension
      const leafPEM = `-----BEGIN CERTIFICATE-----
MIICoTCCAiagAwIBAgIURm9on7zDvhPmPdvRSid8Qc1W0nEwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjIwNzIyMjExMTUxWhcNMjIwNzIyMjEyMTUxWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEWfKrK8Ky+duY5xEgexxh2fhS+6RWxAodzdaQ
3p75wvumEzpWXMynav3upjUqGw28+ZPnTpAYkryk/zl3pKRUEKOCAUUwggFBMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUHOAT
bi5c3xsJdYKpMmkF/8QPVX8wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzAB
AQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQC
BHwEegB4AHYACGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3IAAAGCJ8Ce
nAAABAMARzBFAiEAueywtShv7qINRCpAnajFJgvWrnazEdcfrO/xx/yTyFwCIE41
5V1imhqE+aiF52Idmzr57Y5//QJgZ5E5vadkxefQMAoGCCqGSM49BAMDA2kAMGYC
MQDYQen2LUbFkSmg2mb9hXjmNL6TNp8b8xJSje72ZYhqiuika4CyQkcByHsbORky
vjICMQDgfIBIFgnkBIn0UIacFvoF6RWlg/bmkdftHVkdDS59Uv24OpwoGndgoG8w
tLtOthg=
-----END CERTIFICATE-----`;
      const subject = x509Certificate.parse(leafPEM);

      describe('when the SCTs are valid', () => {
        // Fulcio intermediate certificate
        const issuerPEM = `-----BEGIN CERTIFICATE-----
MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3Jl
LmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV7
7LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS
0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYB
BQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjp
KFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZI
zj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJR
nZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsP
mygUY7Ii2zbdCdliiow=
-----END CERTIFICATE-----`;
        const issuer = x509Certificate.parse(issuerPEM);

        it('returns true', () => {
          expect(subject.extSCT).toBeDefined();
          const results = subject.verifySCTs(issuer, logs);
          expect(results).toBeDefined();
          expect(results).toHaveLength(1);
          expect(results[0].verified).toBe(true);
        });
      });

      describe('when the SCTs are invalid', () => {
        const badIssuer = x509Certificate.parse(certificates.root);

        it('returns false', () => {
          const results = subject.verifySCTs(badIssuer, logs);
          expect(results).toBeDefined();
          expect(results).toHaveLength(1);
          expect(results[0].verified).toBe(false);
        });
      });
    });
  });
});
