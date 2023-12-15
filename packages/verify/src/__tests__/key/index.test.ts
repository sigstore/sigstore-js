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
import { fromPartial } from '@total-typescript/shoehorn';
import { VerificationError } from '../../error';
import { verifyCertificate, verifyPublicKey } from '../../key';
import bundles from '../__fixtures__/bundles/v01';

import type { CertAuthority, TLogAuthority, TrustMaterial } from '../../trust';

describe('verifyCertificate', () => {
  const bundle = bundles.signature.valid.withSigningCert;

  const bundleCert =
    bundle.verificationMaterial.x509CertificateChain.certificates[0];
  const leaf = X509Certificate.parse(bundleCert.rawBytes);

  const timestamps = [
    new Date(
      Number(bundle.verificationMaterial.tlogEntries[0].integratedTime) * 1000
    ),
  ];

  // Certificates for public-good Fulcio
  const rootCert =
    'MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ';
  const intCert =
    'MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow=';

  // Key for public-good Fulcio ctlog
  const keyBytes = Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==',
    'base64'
  );

  const certAuthority: CertAuthority = {
    certChain: [
      X509Certificate.parse(rootCert),
      X509Certificate.parse(intCert),
    ],
    validFor: { start: new Date(0), end: new Date('2100-01-01') },
  };

  const ctlogAuthority: TLogAuthority = {
    logID: crypto.hash(keyBytes),
    publicKey: crypto.createPublicKey(keyBytes),
    validFor: { start: new Date(0), end: new Date('2100-01-01') },
  };

  describe('when there are no matching certificate authorities', () => {
    const trustMaterial = fromPartial<TrustMaterial>({
      certificateAuthorities: [],
      ctlogs: [],
    });

    it('throws an error', () => {
      expect(() =>
        verifyCertificate(leaf, timestamps, trustMaterial)
      ).toThrowWithCode(VerificationError, 'CERTIFICATE_ERROR');
    });
  });

  describe('when the certificate was NOT issued by a trusted CA', () => {
    const incorrectCA: CertAuthority = {
      certChain: [
        X509Certificate.parse(
          'MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=='
        ),
      ],
      validFor: { start: new Date(0), end: new Date('2100-01-01') },
    };

    const trustMaterial = fromPartial<TrustMaterial>({
      certificateAuthorities: [incorrectCA],
      ctlogs: [],
    });

    it('throws an error', () => {
      expect(() =>
        verifyCertificate(leaf, timestamps, trustMaterial)
      ).toThrowWithCode(VerificationError, 'CERTIFICATE_ERROR');
    });
  });

  describe('when there are no matching ctlog authorities', () => {
    const trustMaterial = fromPartial<TrustMaterial>({
      certificateAuthorities: [certAuthority],
      ctlogs: [],
    });

    it('throws an error', () => {
      expect(() =>
        verifyCertificate(leaf, timestamps, trustMaterial)
      ).toThrowWithCode(VerificationError, 'CERTIFICATE_ERROR');
    });
  });

  describe('when specified timestamp falls outside the certs validity window', () => {
    const unmatchedTimestamps = [new Date(0)];
    const trustMaterial = fromPartial<TrustMaterial>({
      certificateAuthorities: [certAuthority],
      ctlogs: [ctlogAuthority],
    });

    it('throws an error', () => {
      expect(() =>
        verifyCertificate(leaf, unmatchedTimestamps, trustMaterial)
      ).toThrowWithCode(VerificationError, 'CERTIFICATE_ERROR');
    });
  });

  describe('when everything is valid (legacy cert)', () => {
    const trustMaterial = fromPartial<TrustMaterial>({
      certificateAuthorities: [certAuthority],
      ctlogs: [ctlogAuthority],
    });

    it('returns the verifier', () => {
      const result = verifyCertificate(leaf, timestamps, trustMaterial);
      expect(result.scts).toHaveLength(1);
      expect(result.scts[0]).toEqual(ctlogAuthority.logID);
      expect(result.signer).toBeDefined();
      expect(result.signer.identity).toBeDefined();
      expect(result.signer.identity?.subjectAlternativeName).toBeDefined();
      expect(result.signer.identity?.extensions?.issuer).toEqual(
        'https://github.com/login/oauth'
      );
      expect(result.signer.key).toBeDefined();
    });
  });

  describe('when everything is valid (new-style cert)', () => {
    const signingCert =
      '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';

    const leaf = X509Certificate.parse(signingCert);

    const timestamps = [new Date('2023-08-29T15:45:00.000Z')];
    const trustMaterial = fromPartial<TrustMaterial>({
      certificateAuthorities: [certAuthority],
      ctlogs: [ctlogAuthority],
    });

    it('returns the verifier', () => {
      const result = verifyCertificate(leaf, timestamps, trustMaterial);
      expect(result.scts).toHaveLength(1);
      expect(result.scts[0]).toEqual(ctlogAuthority.logID);
      expect(result.signer).toBeDefined();
      expect(result.signer.identity).toBeDefined();
      expect(result.signer.identity?.subjectAlternativeName).toBeDefined();
      expect(result.signer.identity?.extensions?.issuer).toEqual(
        'https://token.actions.githubusercontent.com'
      );
      expect(result.signer.key).toBeDefined();
    });
  });

  describe('when a public key is supplied', () => {
    const bundle = bundles.signature.valid.withPublicKey;
    const key = bundles.signature.publicKey;

    const hint = bundle.verificationMaterial.publicKey.hint;
    const timestamps = [new Date()];

    describe('when the public key is not valid for the timestamp', () => {
      const trustMaterial = fromPartial<TrustMaterial>({
        publicKey: () => ({
          publicKey: crypto.createPublicKey(key),
          validFor: () => false,
        }),
      });

      it('throws an error', () => {
        expect(() =>
          verifyPublicKey(hint, timestamps, trustMaterial)
        ).toThrowWithCode(VerificationError, 'PUBLIC_KEY_ERROR');
      });
    });

    describe('when everything is valid', () => {
      const trustMaterial = fromPartial<TrustMaterial>({
        publicKey: () => ({
          publicKey: crypto.createPublicKey(key),
          validFor: () => true,
        }),
      });

      it('returns the verifier', () => {
        const result = verifyPublicKey(hint, timestamps, trustMaterial);
        expect(result).toBeDefined();
        expect(result.identity).toBeUndefined();
        expect(result.key.asymmetricKeyType).toEqual('ec');
      });
    });
  });
});
