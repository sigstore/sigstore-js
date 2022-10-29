import { createPublicKey } from 'crypto';
import { Bundle, HashAlgorithm } from '../types/bundle';
import { verifyTLogSET } from './verify';

describe('verifyTLogSET', () => {
  const logID = Buffer.from(
    'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=',
    'base64'
  );

  const tlogKey = createPublicKey(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`);

  const keys = { [logID.toString('hex')]: tlogKey };

  describe('when a message signature Bundle is provided', () => {
    const set = Buffer.from(
      'MEYCIQDugFgwSW5qfX7ML0lVt7xsam957nt2vHZqzl5g7r+/2AIhAKl/oE86GFVM/EfQUnVgvBDm4+HNEdJIIlSnCRi47Efo',
      'base64'
    );
    describe('when the SET is valid', () => {
      const bundle = createMessageSignatureBundle(logID, set);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogSET(bundle, keys)).not.toThrow();
      });
    });

    describe('when there is no key for the logID', () => {
      const bundle = createMessageSignatureBundle(logID, set);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, {})).toThrow(
          /no key found for logID/
        );
      });
    });

    describe('when there is no signature in the bundle', () => {
      const bundle = createMessageSignatureBundle(logID, undefined);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, keys)).toThrow(
          /no SET found in bundle/
        );
      });
    });

    describe('when the SET does not match', () => {
      const bundle = createMessageSignatureBundle(
        logID,
        Buffer.from('invalid')
      );

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, keys)).toThrow(
          /transparency log SET verification failed/
        );
      });
    });
  });

  describe('when a DSSE Bundle is provided', () => {
    const set = Buffer.from(
      'MEYCIQCQbPmAJdeX6FQTaRlqJfIX+MTafAu3Gfp3KweK+Il1BgIhAL3EukkUb3DbCE0hIssL6O/XD/mOAWpwmTb6Tc47Gu+q',
      'base64'
    );

    describe('when the SET is valid', () => {
      const bundle = createDSSEBundle(logID, set);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogSET(bundle, keys)).not.toThrow();
      });
    });
  });
});

function createMessageSignatureBundle(logID: Buffer, set?: Buffer): Bundle {
  const cert1 = Buffer.from(
    'MIICoTCCAiagAwIBAgIUJECMzULTYb8pG/ngCsiEYTYVdJIwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjIxMDI3MTc0NDUwWhcNMjIxMDI3MTc1NDUwWjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkxX4UccsTnR4VFxh60iHA46oZiocR8FMS612jkzhEEU0+Eo3qRy8psz8IpMcosbIIRN1XgvtGb0Zmd713E5jdKOCAUUwggFBMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUSUdVzmvSY3fvzNuJLENw7wxIIQwwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYACGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3IAAAGEGovy/AAABAMARzBFAiBJznTgnpncOXrjpTq6Z/lEXGck6ArCnzwp5/t6klWh4QIhAN2h18Ja1drrGva6P8wp2Cfo8xJbplH7O1vem1xlTjvZMAoGCCqGSM49BAMDA2kAMGYCMQCKIPWXYL91e+AUkT17CRrsrAARim/9nkI2V+EuIwPdbej7sORqB4cV6KXUcH2zyssCMQCqiRZs0NXqQDDUEYpnFvItqdsxHaCyDazsZ8c1IMBT7jpzToWTNooHkRnou7ZEjCc=',
    'base64'
  );
  const cert2 = Buffer.from(
    'MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=',
    'base64'
  );
  const cert3 = Buffer.from(
    'MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ',
    'base64'
  );

  return {
    mediaType: 'application/vnd.in-toto+json',
    content: {
      $case: 'messageSignature',
      messageSignature: {
        signature: Buffer.from(
          'MEUCIDL0+G2/xh0cbb37XnXQu+BoS5WoxUUk8in0s4FJkNuDAiEAhJ/tRjVfxd7W9XGN09DkzOCW7Duwx6SHH8gz9U7Pi0c=',
          'base64'
        ),
        messageDigest: {
          algorithm: HashAlgorithm.SHA2_256,
          digest: Buffer.from(
            'ktuJxCfXBG750cocBM1bVBEbxa169IgdrOLH/axuSDA=',
            'base64'
          ),
        },
      },
    },
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: {
          certificates: [
            { derBytes: cert1 },
            { derBytes: cert2 },
            { derBytes: cert3 },
          ],
        },
      },
    },
    verificationData: {
      timestampVerificationData: {
        rfc3161Timestamps: [],
      },
      tlogEntries: [
        {
          logIndex: '5993558',
          logId: {
            keyId: logID,
          },
          kindVersion: { kind: 'hashedrekord', version: '0.0.1' },
          integratedTime: '1666892690',
          inclusionPromise: set ? { signedEntryTimestamp: set } : undefined,
        },
      ],
    },
  };
}

function createDSSEBundle(logID: Buffer, set?: Buffer): Bundle {
  const cert1 = Buffer.from(
    'MIICoDCCAiagAwIBAgIUYyI8hSRQrdKIHIaS2jvAIHxuAc4wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjIxMDI5MDAyMzI3WhcNMjIxMDI5MDAzMzI3WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsRpGkBXeDZdk5LA8VmNHYV/G8vNCAl+8KJlKAfZf1DQJMfr8G+I8urKzVqFjYJX6c1+bXMhpliHpICDxYPC2GqOCAUUwggFBMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUic6XGniEFYi/W82D1XgoB64daSYwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYACGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3IAAAGEIR9DbwAABAMARzBFAiEAtnv+OEMJQHPFG8NzEkc5TfGBbbBwKcNVCEhXGV39AfsCIDbmfnIfSSCKVuH5UtYzFwo+w8R+cHYYqMLJcEPbtPUpMAoGCCqGSM49BAMDA2gAMGUCMQC1GQ0biQbYlZEkviEjnjKEhzD5P4IsmsvXDpSTOcF8UNWjHo4yFzGrOrfTAD90p7UCMH9um7V4MbZK8MKEOc1HppfcXQinzo7c6EKLWC5PSMDTRaqj6gi77LNVf7cG8G8lKw==',
    'base64'
  );
  const cert2 = Buffer.from(
    'MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=',
    'base64'
  );
  const cert3 = Buffer.from(
    'MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ',
    'base64'
  );

  return {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
    content: {
      $case: 'dsseEnvelope',
      dsseEnvelope: {
        payload: Buffer.from('aGVsbG8sIHdvcmxkIQ==', 'base64'),
        payloadType: 'text/plain',
        signatures: [
          {
            keyid: '',
            sig: Buffer.from(
              'MEYCIQDA8kr4Cz5CPvfTSEEqZtOM3Scy3lTEI11rWLBUGKCeSwIhAOc45GLyZngDj1vpNo/SMOJYG/knygFBd5y1Boe+p++S',
              'base64'
            ),
          },
        ],
      },
    },
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: {
          certificates: [
            { derBytes: cert1 },
            { derBytes: cert2 },
            { derBytes: cert3 },
          ],
        },
      },
    },
    verificationData: {
      timestampVerificationData: {
        rfc3161Timestamps: [],
      },
      tlogEntries: [
        {
          logIndex: '6071591',
          logId: {
            keyId: logID,
          },
          kindVersion: { kind: 'intoto', version: '0.0.2' },
          integratedTime: '1667003008',
          inclusionPromise: set ? { signedEntryTimestamp: set } : undefined,
        },
      ],
    },
  };
}
