/*
Copyright 2022 The Sigstore Authors.

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
import { createPublicKey } from 'crypto';
import { Bundle, HashAlgorithm } from '../types/bundle';
import { pem } from '../util';
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

  const tlogKeys = { [logID.toString('hex')]: tlogKey };

  describe('when a message signature Bundle is provided', () => {
    const set = Buffer.from(
      'MEYCIQDugFgwSW5qfX7ML0lVt7xsam957nt2vHZqzl5g7r+/2AIhAKl/oE86GFVM/EfQUnVgvBDm4+HNEdJIIlSnCRi47Efo',
      'base64'
    );
    describe('when the SET is valid', () => {
      const bundle = createMessageSignatureBundle(logID, set);
      const publicKey = getPublicKey(bundle);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogSET(bundle, publicKey, tlogKeys)).not.toThrow();
      });
    });

    describe('when there is no key for the logID', () => {
      const bundle = createMessageSignatureBundle(logID, set);
      const publicKey = getPublicKey(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, publicKey, {})).toThrow(
          /no key found for logID/
        );
      });
    });

    describe('when there is no signature in the bundle', () => {
      const bundle = createMessageSignatureBundle(logID, undefined);
      const publicKey = getPublicKey(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, publicKey, tlogKeys)).toThrow(
          /no SET found in bundle/
        );
      });
    });

    describe('when the SET does not match', () => {
      const bundle = createMessageSignatureBundle(
        logID,
        Buffer.from('invalid')
      );
      const publicKey = getPublicKey(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, publicKey, tlogKeys)).toThrow(
          /transparency log SET verification failed/
        );
      });
    });
  });

  describe('when a DSSE Bundle is provided', () => {
    const set = Buffer.from(
      'MEYCIQDCDqNKrxg0g2J/psG5ypPTcxiEoSXSj93G1GhaitBnswIhAM6WDzaJTCkQ2h39jv7vmthAlKZQNRH6Stqxy0Fi4k+C',
      'base64'
    );

    describe('when the SET is valid', () => {
      const bundle = createDSSEBundle(logID, set);
      const publicKey = getPublicKey(bundle);

      it('does NOT throw an error', () => {
        expect(() => verifyTLogSET(bundle, publicKey, tlogKeys)).not.toThrow();
      });
    });

    describe('when the SET does not match', () => {
      const bundle = createDSSEBundle(logID, Buffer.from('invalid'));
      const publicKey = getPublicKey(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogSET(bundle, publicKey, tlogKeys)).toThrow(
          /transparency log SET verification failed/
        );
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
            { rawBytes: cert1 },
            { rawBytes: cert2 },
            { rawBytes: cert3 },
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
          inclusionProof: undefined,
        },
      ],
    },
  };
}

function createDSSEBundle(logID: Buffer, set?: Buffer): Bundle {
  const cert1 = Buffer.from(
    'MIICoTCCAiagAwIBAgIUAilwtOGnYZAHZFmV+0z6j8c+yIQwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjIxMTAyMjMyNDM0WhcNMjIxMTAyMjMzNDM0WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdEE+u7yTkC2uG819DRlmMzYSoGoEP4r8glaiK7foqjNODPS7b3s5p9xlAey4fFHHhdHktmpVAZGD3gy/3UKqXqOCAUUwggFBMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0ZCaKJ81FfD8BnPlAEaZ5+H5CMEwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGEOqkmUgAABAMARzBFAiAAj+CKr8Qaw8xxQInoQtf1V15vPeGCaKNs23yaaQAl1wIhAPmzjDmJi69oxaz/5OYjrUg7XNl9RUCRIZ8ZLFgsl42jMAoGCCqGSM49BAMDA2kAMGYCMQCpj0ghinAEs36KiLOegtym8TEAAAyI9PMK+WZzpm3aGXDA0phyOZjmtEd0wPeDB1QCMQCMvZkgu96zId0esW3oYsDaIFd5NUGa3lXuBj3Lc0MMRvfmyG49I4Gj9qV7dgKEm2o=',
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
              'MEUCIQCVCPbzc4aPZMKpXnwuqbUp6WNDqSHFVfvPmSVSYz+sIgIgEUltpzCXjguuMHlx8qXHJCuH6ptaTmW57llQJRGqQfc=',
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
            { rawBytes: cert1 },
            { rawBytes: cert2 },
            { rawBytes: cert3 },
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
          logIndex: '6387817',
          logId: {
            keyId: logID,
          },
          kindVersion: { kind: 'intoto', version: '0.0.2' },
          integratedTime: '1667431475',
          inclusionPromise: set ? { signedEntryTimestamp: set } : undefined,
          inclusionProof: undefined,
        },
      ],
    },
  };
}

function getPublicKey(bundle: Bundle): string {
  if (bundle.verificationMaterial?.content?.$case === 'x509CertificateChain') {
    const cert =
      bundle.verificationMaterial.content.x509CertificateChain.certificates[0];
    return pem.fromDER(cert.rawBytes);
  } else {
    fail('no public key found');
  }
}
