/*
Copyright 2022 GitHub, Inc

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
import { Fulcio, Rekor } from './client';
import { Signer } from './sign';

describe('Signer', () => {
  const fulcioBaseURL = 'http://localhost:8001';
  const rekorBaseURL = 'http://localhost:8002';
  const jwtPayload = {
    iss: 'https://example.com',
    sub: 'foo@bar.com',
  };
  const jwt = `.${Buffer.from(JSON.stringify(jwtPayload)).toString('base64')}.`;

  const fulcio = new Fulcio({ baseURL: fulcioBaseURL });
  const rekor = new Rekor({ baseURL: rekorBaseURL });
  const idp = { getToken: () => Promise.resolve(jwt) };

  const subject = new Signer({
    fulcio,
    rekor,
    identityProviders: [idp],
  });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#sign', () => {
    // Input
    const payload = Buffer.from('Hello, world!');

    describe('when no identity provider returns a token', () => {
      const noIDTokenSubject = new Signer({
        fulcio,
        rekor,
        identityProviders: [],
      });

      it('throws an error', async () => {
        await expect(noIDTokenSubject.sign(payload)).rejects.toThrow(
          'No identity token provided'
        );
      });
    });

    describe('when Fulcio returns an error', () => {
      beforeEach(() => {
        nock(fulcioBaseURL).post('/api/v1/signingCert').reply(500, {});
      });

      it('returns an error', async () => {
        await expect(subject.sign(payload)).rejects.toThrow(
          'HTTP Error: 500 Internal Server Error'
        );
      });
    });

    describe('when Fulcio returns successfully', () => {
      // Fulcio output
      const certificate = `-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----`;

      beforeEach(() => {
        // Mock Fulcio request
        nock(fulcioBaseURL)
          .matchHeader('Accept', 'application/pem-certificate-chain')
          .matchHeader('Content-Type', 'application/json')
          .matchHeader('Authorization', `Bearer ${jwt}`)
          .post('/api/v1/signingCert', {
            publicKey: { content: /.+/i },
            signedEmailAddress: /.+/i,
          })
          .reply(200, certificate);
      });

      describe('when Rekor returns successfully', () => {
        // Rekor output
        const signature = 'ABC123';
        const b64Cert = Buffer.from(certificate).toString('base64');
        const uuid =
          '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

        const signatureBundle = {
          spec: {
            signature: {
              content: signature,
              publicKey: { content: b64Cert },
            },
          },
        };

        const rekorEntry = {
          [uuid]: {
            body: Buffer.from(JSON.stringify(signatureBundle)).toString(
              'base64'
            ),
            integratedTime: 1654015743,
            logID:
              'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
            logIndex: 2513258,
            verification: {
              signedEntryTimestamp:
                'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
            },
          },
        };

        beforeEach(() => {
          // Mock Rekor request
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .matchHeader('Content-Type', 'application/json')
            .post('/api/v1/log/entries')
            .reply(201, rekorEntry);
        });

        it('returns a signature bundle', async () => {
          const signedPayload = await subject.sign(payload);

          expect(signedPayload).toBeTruthy();
          expect(signedPayload.base64Signature).toBeTruthy();
          expect(signedPayload.cert).toBe(b64Cert);
          expect(signedPayload.bundle).toBeDefined();
        });
      });

      describe('when Rekor returns an error', () => {
        beforeEach(() => {
          nock(rekorBaseURL)
            .matchHeader('Accept', 'application/json')
            .matchHeader('Content-Type', 'application/json')
            .post('/api/v1/log/entries')
            .reply(500, {});
        });

        it('returns an error', async () => {
          await expect(subject.sign(payload)).rejects.toThrow(
            'HTTP Error: 500 Internal Server Error'
          );
        });
      });
    });
  });
});
