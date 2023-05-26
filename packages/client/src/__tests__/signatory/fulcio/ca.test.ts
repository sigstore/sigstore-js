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
import nock from 'nock';
import { InternalError } from '../../../error';
import { CAClient } from '../../../signatory/fulcio/ca';

describe('CAClient', () => {
  const fulcioBaseURL = 'http://localhost:8080';

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new CAClient({ fulcioBaseURL });
      expect(client).toBeDefined();
    });
  });

  describe('createSigningCertificate', () => {
    const subject = new CAClient({ fulcioBaseURL });

    const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n`;
    const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----\n`;
    const certChain = [leafCertificate, rootCertificate];

    // Request data
    const identityToken = 'a.b.c';

    const publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtZO/hiYFB3WveI+iYoN4I6w17rSA
tbn02XdfIl+ZhQqUZv88dgDB86bfKyoOokA7fagAEOulkquhKKoOxdOySQ==
-----END PUBLIC KEY-----`;
    const challenge = Buffer.from('challenge');

    const certRequest = {
      credentials: {
        oidcIdentityToken: identityToken,
      },
      publicKeyRequest: {
        publicKey: {
          algorithm: 'ECDSA',
          content: publicKey,
        },
        proofOfPossession: challenge.toString('base64'),
      },
    };

    describe('when Fulcio returns a valid response (with embedded SCT)', () => {
      beforeEach(() => {
        nock(fulcioBaseURL)
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('User-Agent', new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'))
          .post('/api/v2/signingCert', certRequest)
          .reply(201, {
            signedCertificateEmbeddedSct: {
              chain: { certificates: certChain },
            },
          });
      });

      it('returns the certificate chain', async () => {
        const result = await subject.createSigningCertificate(
          identityToken,
          publicKey,
          challenge
        );

        expect(result).toEqual([leafCertificate, rootCertificate]);
      });
    });

    describe('when Fulcio returns a valid response (with detached SCT)', () => {
      beforeEach(() => {
        nock(fulcioBaseURL)
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('User-Agent', new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'))
          .post('/api/v2/signingCert', certRequest)
          .reply(201, {
            signedCertificateDetachedSct: {
              chain: { certificates: certChain },
              signedCertificateTimestamp: 'sct',
            },
          });
      });

      it('returns the certificate chain', async () => {
        const result = await subject.createSigningCertificate(
          identityToken,
          publicKey,
          challenge
        );

        expect(result).toEqual([leafCertificate, rootCertificate]);
      });
    });

    describe('when Fulcio returns an error response', () => {
      beforeEach(() => {
        nock(fulcioBaseURL)
          .matchHeader('Accept', 'application/pem-certificate-chain')
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('Authorization', `Bearer ${identityToken}`)
          .matchHeader('User-Agent', new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'))
          .post('/api/v1/signingCert', certRequest)
          .reply(500, {});
      });

      it('throws an error', async () => {
        await expect(
          subject.createSigningCertificate(identityToken, publicKey, challenge)
        ).rejects.toThrowWithCode(
          InternalError,
          'CA_CREATE_SIGNING_CERTIFICATE_ERROR'
        );
      });
    });
  });
});
