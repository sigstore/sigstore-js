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
import { X509Certificate, crypto } from '@sigstore/core';
import { VerificationError } from '../../error';
import { verifySCTs } from '../../key/sct';
import { certificates } from '../__fixtures__/certs';

import type { TLogAuthority } from '../../trust';

describe('verifySCTs', () => {
  // Fulcio ctfe key
  const ctfe =
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==';

  const ctl: TLogAuthority = {
    logID: Buffer.from(
      'CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I=',
      'base64'
    ),
    publicKey: crypto.createPublicKey(Buffer.from(ctfe, 'base64')),
    validFor: { start: new Date('2000-01-01'), end: new Date('2999-01-01') },
  };

  const logs: TLogAuthority[] = [ctl];

  describe('when the certificate does NOT have an SCT extension', () => {
    const leaf = X509Certificate.parse(certificates.leaf);
    const issuer = X509Certificate.parse(certificates.intermediate);

    it('returns an empty array', () => {
      expect(verifySCTs(leaf, issuer, logs)).toHaveLength(0);
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
    const leaf = X509Certificate.parse(leafPEM);

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
      const issuer = X509Certificate.parse(issuerPEM);

      it('returns the list of verified SCTs', () => {
        expect(leaf.extSCT).toBeDefined();
        const results = verifySCTs(leaf, issuer, logs);
        expect(results).toBeDefined();
        expect(results).toHaveLength(1);
        expect(results[0]).toEqual(ctl.logID);
      });
    });

    describe('when the SCTs are invalid', () => {
      const badIssuer = X509Certificate.parse(certificates.root);

      it('throws an error', () => {
        expect(() => verifySCTs(leaf, badIssuer, logs)).toThrowWithCode(
          VerificationError,
          'CERTIFICATE_ERROR'
        );
      });
    });
  });
});
