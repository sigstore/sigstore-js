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
import nock from 'nock';

import { Fulcio } from './fulcio';

describe('Fulcio', () => {
  const baseURL = 'http://localhost:8000';
  const subject = new Fulcio({ baseURL });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#createSigningCertificate', () => {
    const certRequest = {
      identityToken: `a.b.c`,
      publicKey:
        'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==',
      challenge: 'MEUCIEntw6QwoyDHb52HUIUVDnqFeGBI4oaCBMCoOtcbVKQ=',
    };

    describe('when the certificate request is valid', () => {
      const certificate = `-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----`;

      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Accept', 'application/pem-certificate-chain')
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('Authorization', `Bearer ${certRequest.identityToken}`)
          .post('/api/v1/signingCert', {
            publicKey: { content: certRequest.publicKey },
            signedEmailAddress: certRequest.challenge,
          })
          .reply(200, certificate);
      });

      it('returns the signing certificate', async () => {
        const result = await subject.createSigningCertificate(certRequest);
        expect(result).toBe(certificate);
      });
    });

    describe('when the certificate request is invalid', () => {
      const responseBody = {
        code: 400,
        message: 'Invalid certificate request',
      };

      beforeEach(() => {
        nock(baseURL).post('/api/v1/signingCert').reply(400, responseBody);
      });

      it('returns an error', async () => {
        await expect(
          subject.createSigningCertificate(certRequest)
        ).rejects.toThrow('HTTP Error: 400 Bad Request');
      });
    });
  });
});
