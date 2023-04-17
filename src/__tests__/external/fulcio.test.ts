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

import {
  Fulcio,
  SigningCertificateRequest,
  SigningCertificateResponse,
} from '../../external/fulcio';

describe('Fulcio', () => {
  const baseURL = 'http://localhost:8000';
  const subject = new Fulcio({ baseURL });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#createSigningCertificate', () => {
    const identityToken = `a.b.c`;
    const certRequest = {
      credentials: {
        oidcIdentityToken: identityToken,
      },
      publicKeyRequest: {
        publicKey: {
          algorithm: 'ECDSA',
          content:
            'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==',
        },
        proofOfPossession: 'MEUCIEntw6QwoyDHb52HUIUVDnqFeGBI4oaCBMCoOtcbVKQ=',
      },
    } satisfies SigningCertificateRequest;

    describe('when the certificate request is valid', () => {
      const certificateResponse: SigningCertificateResponse = {
        signedCertificateEmbeddedSct: {
          chain: {
            certificates: [
              `-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----`,
            ],
          },
        },
      };

      beforeEach(() => {
        nock(baseURL)
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('User-Agent', new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'))
          .post('/api/v2/signingCert', certRequest)
          .reply(200, certificateResponse);
      });

      it('returns the signing certificate', async () => {
        const result = await subject.createSigningCertificate(certRequest);
        expect(result).toEqual(certificateResponse);
      });
    });

    describe('when the certificate request is invalid', () => {
      const responseBody = {
        code: 400,
        message: 'Invalid certificate request',
      };

      beforeEach(() => {
        nock(baseURL).post('/api/v2/signingCert').reply(400, responseBody);
      });

      it('returns an error', async () => {
        await expect(
          subject.createSigningCertificate(certRequest)
        ).rejects.toThrow('HTTP Error: 400 Bad Request');
      });
    });
  });
});
