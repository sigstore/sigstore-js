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
import crypto from 'crypto';
import nock from 'nock';
import { CAClient } from '../../ca';

describe('CAClient', () => {
  const baseURL = 'http://localhost:8080';

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new CAClient({ fulcioBaseURL: baseURL });
      expect(client).toBeDefined();
    });
  });

  describe('createSigningCertificate', () => {
    const subject = new CAClient({ fulcioBaseURL: baseURL });

    const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n`;
    const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----\n`;
    const certChain = [leafCertificate, rootCertificate].join('');

    // Request data
    const identityToken = 'a.b.c';

    const pem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtZO/hiYFB3WveI+iYoN4I6w17rSA
tbn02XdfIl+ZhQqUZv88dgDB86bfKyoOokA7fagAEOulkquhKKoOxdOySQ==
-----END PUBLIC KEY-----`;
    const publicKey = crypto.createPublicKey(pem);
    const challenge = Buffer.from('challenge');

    const certRequest = {
      publicKey: {
        content: publicKey
          .export({ type: 'spki', format: 'der' })
          .toString('base64'),
      },
      signedEmailAddress: challenge.toString('base64'),
    };

    describe('when Fulcio returns a valid response', () => {
      beforeEach(() => {
        // Mock Fulcio request
        nock(baseURL)
          .matchHeader('Accept', 'application/pem-certificate-chain')
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('Authorization', `Bearer ${identityToken}`)
          .matchHeader('User-Agent', new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'))
          .post('/api/v1/signingCert', certRequest)
          .reply(201, certChain);
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
        // Mock Fulcio request
        nock(baseURL)
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
        ).rejects.toThrow('HTTP Error: 500 Internal Server Error');
      });
    });
  });
});
