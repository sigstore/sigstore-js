import { RFC3161Timestamp, X509Certificate } from '@sigstore/core';
import { VerificationError } from '../../error';
import { verifyRFC3161Timestamp } from '../../timestamp/tsa';
import { CertAuthority } from '../../trust';

describe('verifyRFC3161Timestamp', () => {
  const artifact = Buffer.from('hello, world!');
  const tsBytes = Buffer.from(
    'MIICIDADAgEAMIICFwYJKoZIhvcNAQcCoIICCDCCAgQCAQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBpBGcwZQIBAQYJKwYBBAGDvzACMC8wCwYJYIZIAWUDBAIBBCBo5layUeZ+g1i++Eg6sNUcZhnz56Gp8OdYONQf82j3KAIE3q2+7xgTMjAyMzEyMjMwMDE3MDMuMDk5WjADAgEBAgRJlgLSoAAxggFwMIIBbAIBATArMCYxDDAKBgNVBAMTA3RzYTEWMBQGA1UEChMNc2lnc3RvcmUubW9jawIBAjANBglghkgBZQMEAgEFAKCB1TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIzMTIyMzAwMTcwM1owLwYJKoZIhvcNAQkEMSIEIGZcDv7LEHC7SY1TBs1MKmI0MCMChJVp+RCMeyE1mWYZMGgGCyqGSIb3DQEJEAIvMVkwVzBVMFMEIL4AsycoQkVSQDvExPW0mWmW0BAOwQXYUdo6JtfWSP4nMC8wKqQoMCYxDDAKBgNVBAMTA3RzYTEWMBQGA1UEChMNc2lnc3RvcmUubW9jawIBAjAKBggqhkjOPQQDAgRHMEUCIA9EmBywagALb8P8jnn+iZTpb1R9SvQ1QOJ26ICn8SbiAiEAs21Z3xI++DUtb74Yaq0y8Nf5kVPYFtXHQAiG/iBnbKs=',
    'base64'
  );
  const signingPEM = `-----BEGIN CERTIFICATE-----
MIIBuzCCAWGgAwIBAgIBAjAKBggqhkjOPQQDAzAmMQwwCgYDVQQDEwN0c2ExFjAU
BgNVBAoTDXNpZ3N0b3JlLm1vY2swHhcNMjMxMjIzMDAxMzU4WhcNMjQxMjIyMDAx
MzU4WjAuMRQwEgYDVQQDEwt0c2Egc2lnbmluZzEWMBQGA1UEChMNc2lnc3RvcmUu
bW9jazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIVX5ocFJ8M3Z2urwxgiKlpg
cuOI/kU/2Kw3uWtDXhX/J408sXDC+KadlbCOnJW1wk6gnKEw08taYKMN0CVxXbOj
eDB2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoG
CCsGAQUFBwMIMB0GA1UdDgQWBBTw4R0V5NxFPZCd34gdGn1eqokHhjAfBgNVHSME
GDAWgBTw4R0V5NxFPZCd34gdGn1eqokHhjAKBggqhkjOPQQDAwNIADBFAiA8eoBs
sQJyxMwPuAgtqsf33aA6F+9HmJbRmt2dvYBfvgIhAL5bxfSG/5VjH5+DHFX0XF7h
6rqeM9DKbNU0HmxMV0Te
-----END CERTIFICATE-----`;
  const rootPEM = `-----BEGIN CERTIFICATE-----
MIIBnjCCAUSgAwIBAgIBATAKBggqhkjOPQQDAzAmMQwwCgYDVQQDEwN0c2ExFjAU
BgNVBAoTDXNpZ3N0b3JlLm1vY2swHhcNMjMxMjIzMDAxMzU4WhcNMjQxMjIyMDAx
MzU4WjAmMQwwCgYDVQQDEwN0c2ExFjAUBgNVBAoTDXNpZ3N0b3JlLm1vY2swWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAASFV+aHBSfDN2drq8MYIipaYHLjiP5FP9is
N7lrQ14V/yeNPLFwwvimnZWwjpyVtcJOoJyhMNPLWmCjDdAlcV2zo2MwYTAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU8OEdFeTcRT2Q
nd+IHRp9XqqJB4YwHwYDVR0jBBgwFoAU8OEdFeTcRT2Qnd+IHRp9XqqJB4YwCgYI
KoZIzj0EAwMDSAAwRQIhAPRvk0qPFRYZWSIH7UQnG00D0I7pV6B4TPjgpL5VvYaQ
AiB13l000lcAWegsMFZJmPEpKNCndg9LC4ttahNN7REmjw==
-----END CERTIFICATE-----`;

  describe('when the timestamp is valid', () => {
    const ts = RFC3161Timestamp.parse(tsBytes);
    const signingCert = X509Certificate.parse(signingPEM);
    const rootCert = X509Certificate.parse(rootPEM);
    const certAuthority: CertAuthority = {
      certChain: [signingCert, rootCert],
      validFor: { start: new Date(1), end: new Date() },
    };

    it('does NOT throw an error', () => {
      verifyRFC3161Timestamp(ts, artifact, [certAuthority]);
    });
  });

  describe('when there are no matching CAs to verify against', () => {
    const ts = RFC3161Timestamp.parse(tsBytes);
    const certAuthority: CertAuthority = {
      certChain: [],
      validFor: { start: new Date(1), end: new Date() },
    };

    it('throws an error', () => {
      expect(() =>
        verifyRFC3161Timestamp(ts, artifact, [certAuthority])
      ).toThrowWithCode(VerificationError, 'TIMESTAMP_ERROR');
    });
  });

  describe('when the CA certificate chain is invalid', () => {
    const ts = RFC3161Timestamp.parse(tsBytes);
    const signingCert = X509Certificate.parse(signingPEM);

    // No root cert in CA
    const certAuthority: CertAuthority = {
      certChain: [signingCert],
      validFor: { start: new Date(1), end: new Date() },
    };

    it('throws an error', () => {
      expect(() =>
        verifyRFC3161Timestamp(ts, artifact, [certAuthority])
      ).toThrowWithCode(VerificationError, 'TIMESTAMP_ERROR');
    });
  });

  describe('when the artifact does NOT match the signature', () => {
    const ts = RFC3161Timestamp.parse(tsBytes);
    const signingCert = X509Certificate.parse(signingPEM);
    const rootCert = X509Certificate.parse(rootPEM);
    const certAuthority: CertAuthority = {
      certChain: [signingCert, rootCert],
      validFor: { start: new Date(1), end: new Date() },
    };

    it('throws an error', () => {
      expect(() =>
        verifyRFC3161Timestamp(ts, Buffer.from('oops'), [certAuthority])
      ).toThrowWithCode(VerificationError, 'TIMESTAMP_ERROR');
    });
  });

  describe('when the timestamp is outside the validity window of the CA', () => {
    // The signed timestamp is 2030-01-01, but the CA is only valid until 2024-12-22
    const ts = RFC3161Timestamp.parse(
      Buffer.from(
        'MIICGzADAgEAMIICEgYJKoZIhvcNAQcCoIICAzCCAf8CAQMxDzANBglghkgBZQMEAgEFADB0BgsqhkiG9w0BCRABBKBlBGMwYQIBAQYJKwYBBAGDvzACMC8wCwYJYIZIAWUDBAIBBCBo5layUeZ+g1i++Eg6sNUcZhnz56Gp8OdYONQf82j3KAIE3q2+7xgPMjAzMDAxMDEwMDAwMDBaMAMCAQECBEmWAtKgADGCAW8wggFrAgEBMCswJjEMMAoGA1UEAxMDdHNhMRYwFAYDVQQKEw1zaWdzdG9yZS5tb2NrAgECMA0GCWCGSAFlAwQCAQUAoIHVMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMzAwMTAxMDAwMDAwWjAvBgkqhkiG9w0BCQQxIgQghLJ03rMmmDV8/1BGWyKNpH5kwjqbDox0jKcux/tbCKMwaAYLKoZIhvcNAQkQAi8xWTBXMFUwUwQgvgCzJyhCRVJAO8TE9bSZaZbQEA7BBdhR2jom19ZI/icwLzAqpCgwJjEMMAoGA1UEAxMDdHNhMRYwFAYDVQQKEw1zaWdzdG9yZS5tb2NrAgECMAoGCCqGSM49BAMCBEYwRAIgdgyZVd9hRlf0eL6ConhIwsuQD5CcxqluBWgNmU8p03sCIEsO7OyjSVyk8wzMntY17C4UaRCnNKIjjHElijJDUb4t',
        'base64'
      )
    );
    const signingCert = X509Certificate.parse(signingPEM);
    const rootCert = X509Certificate.parse(rootPEM);

    // Setting the validity window to be far in the future so that the timestamp can be
    // compared against the validity window embedded in the CA certs themselves.
    const certAuthority: CertAuthority = {
      certChain: [signingCert, rootCert],
      validFor: { start: new Date(1), end: new Date('2040-01-01') },
    };

    it('throws an error', () => {
      expect(() =>
        verifyRFC3161Timestamp(ts, artifact, [certAuthority])
      ).toThrowWithCode(VerificationError, 'TIMESTAMP_ERROR');
    });
  });
});
