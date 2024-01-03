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
import { createPublicKey } from '../../crypto';
import { RFC3161TimestampVerificationError } from '../../rfc3161/error';
import { RFC3161Timestamp } from '../../rfc3161/timestamp';

describe('RFC3161Timestamp', () => {
  const artifact = Buffer.from('hello, world\n');

  const publicKey =
    '-----BEGIN PUBLIC KEY-----\n' +
    'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEV/zJhNTdu0Fa9hGCUih/JvqEoE81tEWr\n' +
    'AVwUXXhdRgIY9hIFErLhNo6sSOpV9d7Zuy0KWMHhcimCUr41a1732ByVRy3f+Z4Q\n' +
    'hqpsgFMh5b5J90HJLK7HOyUZjehAnvSn\n' +
    '-----END PUBLIC KEY-----\n';

  const ts = Buffer.from(
    'MIIC0TADAgEAMIICyAYJKoZIhvcNAQcCoIICuTCCArUCAQExDTALBglghkgBZQMEAgIwgbwGCyqGSIb3DQEJEAEEoIGsBIGpMIGmAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQghT/5N2Kgbdv3IsTr6d3WbY9j3a6pf1IcPswg2nyXYCACFQCyi6gMhpheZVlBHi153EZai5EdTBgPMjAyMzEyMjAyMTQ5MThaMAMCAQGgNqQ0MDIxFTATBgNVBAoTDEdpdEh1YiwgSW5jLjEZMBcGA1UEAxMQVFNBIFRpbWVzdGFtcGluZ6AAMYIB3jCCAdoCAQEwSjAyMRUwEwYDVQQKEwxHaXRIdWIsIEluYy4xGTAXBgNVBAMTEFRTQSBpbnRlcm1lZGlhdGUCFDQ1ZZrWbr6Lo5+CsIgv6MSK/IcQMAsGCWCGSAFlAwQCAqCCAQUwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMzEyMjAyMTQ5MThaMD8GCSqGSIb3DQEJBDEyBDDvZfw23I/Jvgh0uo9mfMqkEwBvpUfpkmJfUUImoY0Ist/AwWJZxk/yJvNZ464B7vowgYcGCyqGSIb3DQEJEAIvMXgwdjB0MHIEIC4X67ezV4q0OFecnkRUAx6sVRjb/Q6nZYy0cfMfHKgBME4wNqQ0MDIxFTATBgNVBAoTDEdpdEh1YiwgSW5jLjEZMBcGA1UEAxMQVFNBIGludGVybWVkaWF0ZQIUNDVlmtZuvoujn4KwiC/oxIr8hxAwCgYIKoZIzj0EAwMEZzBlAjEAjplaA2ukG3aI+Zf2nqbI8QqpWXTeJGt7OUT23bYDx84OPK/BBn9NR8JkeO41EtN7AjAozvkg9Wi8deG8pZt3Pj/ip+cvL4X3IktD63SS/+rh+/BrYMWawKT6yu8T3MMsQ+E=',
    'base64'
  );

  const subject = RFC3161Timestamp.parse(ts);

  describe('status', () => {
    it('should return the timestamp status', () => {
      expect(subject.status).toEqual(0n);
    });
  });

  describe('signingTime', () => {
    it('should return the timestamp signing time', () => {
      expect(subject.signingTime).toEqual(new Date('2023-12-20T21:49:18.000Z'));
    });
  });

  describe('signerIssuer', () => {
    it('should return the issuer name of the signing certificate', () => {
      expect(subject.signerIssuer).toHaveLength(50);
    });
  });

  describe('signerSerialNumber', () => {
    it('should return the serial number of the signing certificate', () => {
      expect(subject.signerSerialNumber).toEqual(
        Buffer.from('3435659AD66EBE8BA39F82B0882FE8C48AFC8710', 'hex')
      );
    });
  });

  describe('signerDigestAlgorithm', () => {
    it('should return the digest algo used by the signer', () => {
      expect(subject.signerDigestAlgorithm).toEqual('sha384');
    });
  });

  describe('signatureAlgorithm', () => {
    it('should return the timestamp signature algorithm', () => {
      expect(subject.signatureAlgorithm).toEqual('sha384');
    });
  });

  describe('verify', () => {
    describe('when the timestamp is valid', () => {
      const subject = RFC3161Timestamp.parse(ts);
      const key = createPublicKey(publicKey);
      const data = artifact;

      it('does not throw an error', () => {
        expect(() => subject.verify(data, key)).not.toThrow();
      });
    });

    describe('when the artifact does NOT match the one which was signed', () => {
      const subject = RFC3161Timestamp.parse(ts);
      const key = createPublicKey(publicKey);
      const data = Buffer.from('oops');

      it('throws an error', () => {
        expect(() => subject.verify(data, key)).toThrow(
          RFC3161TimestampVerificationError
        );
      });
    });

    describe('when the key does NOT match the signature', () => {
      const subject = RFC3161Timestamp.parse(ts);
      const data = artifact;
      const key = createPublicKey(
        '-----BEGIN PUBLIC KEY-----\n' +
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9DbYBIMQLtWb6J5gtL69jgRwwEfd\n' +
          'tQtKvvG4+o3ZzlOroJplpXaVgF6wBDob++rNG9/AzSaBmApkEwI52XBjWg==\n' +
          '-----END PUBLIC KEY-----\n'
      );

      it('throws an error', () => {
        expect(() => subject.verify(data, key)).toThrow(
          RFC3161TimestampVerificationError
        );
      });
    });

    describe('when the content type is NOT signedData', () => {
      const data = artifact;
      const subject = RFC3161Timestamp.parse(
        Buffer.from(
          'MIICHDADAgEAMIICEwYJKoZIhvcNAQcDoIICBDCCAgACAQMxDzANBglghkgBZQMEAgEFADB0BgsqhkiG9w0BCRABBKBlBGMwYQIBAQYJKwYBBAGDvzACMC8wCwYJYIZIAWUDBAIBBCCFP/k3YqBt2/cixOvp3dZtj2Pdrql/Uhw+zCDafJdgIAIE3q2+7xgPMjAzMDAxMDEwMDAwMDBaMAMCAQECBEmWAtKgADGCAXAwggFsAgEBMCswJjEMMAoGA1UEAxMDdHNhMRYwFAYDVQQKEw1zaWdzdG9yZS5tb2NrAgECMA0GCWCGSAFlAwQCAQUAoIHVMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMzAwMTAxMDAwMDAwWjAvBgkqhkiG9w0BCQQxIgQg9EVaiVg5rwrcg1wj/j99tIJrWKYn60AIthUWerryKLcwaAYLKoZIhvcNAQkQAi8xWTBXMFUwUwQgvgCzJyhCRVJAO8TE9bSZaZbQEA7BBdhR2jom19ZI/icwLzAqpCgwJjEMMAoGA1UEAxMDdHNhMRYwFAYDVQQKEw1zaWdzdG9yZS5tb2NrAgECMAoGCCqGSM49BAMCBEcwRQIhAN7VR7nM4ppVskxDo5PiWGiIaPB6Cf76vRohGAmU5uo7AiAWlZC7auQlm8xTwpBkgJDd0dXsTesTfeMoREFKXdDzMw==',
          'base64'
        )
      );
      const key = createPublicKey(
        '-----BEGIN PUBLIC KEY-----\n' +
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhVfmhwUnwzdna6vDGCIqWmBy44j+\n' +
          'RT/YrDe5a0NeFf8njTyxcML4pp2VsI6clbXCTqCcoTDTy1pgow3QJXFdsw==\n' +
          '-----END PUBLIC KEY-----\n'
      );

      it('throws an error', () => {
        expect(() => subject.verify(data, key)).toThrow(
          RFC3161TimestampVerificationError
        );
      });
    });

    describe('when the encapsulated content type is NOT tstInfo', () => {
      const data = artifact;
      const subject = RFC3161Timestamp.parse(
        Buffer.from(
          'MIICITADAgEAMIICGAYJKoZIhvcNAQcCoIICCTCCAgUCAQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBaBpBGcwZQIBAQYJKwYBBAGDvzACMC8wCwYJYIZIAWUDBAIBBCCFP/k3YqBt2/cixOvp3dZtj2Pdrql/Uhw+zCDafJdgIAIE3q2+7xgTMjAyMzEyMjExOTEwNTguNDI2WjADAgEBAgRJlgLSoAAxggFxMIIBbQIBATArMCYxDDAKBgNVBAMTA3RzYTEWMBQGA1UEChMNc2lnc3RvcmUubW9jawIBAjANBglghkgBZQMEAgEFAKCB1TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQUwHAYJKoZIhvcNAQkFMQ8XDTIzMTIyMTE5MTA1OFowLwYJKoZIhvcNAQkEMSIEILhMPeMNPj1iPtE7ztAzXNMco3qGrxS5LwFORL66zN6PMGgGCyqGSIb3DQEJEAIvMVkwVzBVMFMEIIdLV5cij9fs6Nm62roSAclDR2JC116C4Hp61tEMWTsZMC8wKqQoMCYxDDAKBgNVBAMTA3RzYTEWMBQGA1UEChMNc2lnc3RvcmUubW9jawIBAjAKBggqhkjOPQQDAgRIMEYCIQDQN2PgaZ38no/tP/NpncFPskEh1tVGqj4n+pe4VeGYPgIhAKtXSYiKZARsIHepbROedQvFnq0JP3mZaQ+r1kYI5Tuk',
          'base64'
        )
      );
      const key = createPublicKey(
        '-----BEGIN PUBLIC KEY-----\n' +
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEblxL3hYMGPJAyKCRfNH9zoCbLtb\n' +
          'dOuVnDwPoAUK/sw7vjBNtqaVbet0dTymhDiMLRoKlq95OIM3Hl9Fvbi0gg==\n' +
          '-----END PUBLIC KEY-----\n'
      );

      it('throws an error', () => {
        expect(() => subject.verify(data, key)).toThrow(
          RFC3161TimestampVerificationError
        );
      });
    });

    describe('when the timestamp token is missing', () => {
      const data = artifact;
      const key = createPublicKey(publicKey);
      const subject = RFC3161Timestamp.parse(
        Buffer.from('30053003020100', 'hex')
      );
      it('throws an error', () => {
        expect(() => subject.verify(data, key)).toThrow(
          RFC3161TimestampVerificationError
        );
      });
    });

    describe('when the signed message does NOT match the tstInfo', () => {
      const data = artifact;
      const subject = RFC3161Timestamp.parse(
        Buffer.from(
          'MIICHzADAgEAMIICFgYJKoZIhvcNAQcCoIICBzCCAgMCAQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBpBGcwZQIBAQYJKwYBBAGDvzACMC8wCwYJYIZIAWUDBAIBBCCFP/k3YqBt2/cixOvp3dZtj2Pdrql/Uhw+zCDafJdgIAIE3q2+7xgTMjAyMzEyMjExOTE2MzIuNzE4WjADAgEBAgRJlgLSoAAxggFvMIIBawIBATArMCYxDDAKBgNVBAMTA3RzYTEWMBQGA1UEChMNc2lnc3RvcmUubW9jawIBAjANBglghkgBZQMEAgEFAKCB1TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIzMTIyMTE5MTYzMlowLwYJKoZIhvcNAQkEMSIEIJuptzDaKrDb239c8R2sNeHm6xCkRN81uAsObeDpWZHJMGgGCyqGSIb3DQEJEAIvMVkwVzBVMFMEILXG2YeUshi7GamxglcNv0Udq53SwfXSM6LhJbmA82OQMC8wKqQoMCYxDDAKBgNVBAMTA3RzYTEWMBQGA1UEChMNc2lnc3RvcmUubW9jawIBAjAKBggqhkjOPQQDAgRGMEQCIARr+DJVotgq2uQAEoTzkSg2Fo/LHarefdlxvUUvvxZfAiAzCJhmXfchOfsl6wlPfV9zCZsJXIMG4yY7sCQOS/wiHQ==',
          'base64'
        )
      );
      const key = createPublicKey(
        '-----BEGIN PUBLIC KEY-----\n' +
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvBYWB7Aqp6+E4SeBCAkBWGhQZW2O\n' +
          'u3T+xRv5VpDSfvYJPT46EMpov8AJkR1G4rs0iV1csuammXKF+BQzvLh/qQ==\n' +
          '-----END PUBLIC KEY-----\n'
      );

      it('throws an error', () => {
        expect(() => subject.verify(data, key)).toThrow(
          RFC3161TimestampVerificationError
        );
      });
    });
  });
});
