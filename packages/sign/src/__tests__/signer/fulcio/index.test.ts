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
import assert from 'assert';
import nock from 'nock';
import { InternalError } from '../../../error';
import { FulcioSigner, FulcioSignerOptions } from '../../../signer/fulcio';

import type { IdentityProvider } from '../../../identity';
import type { Signer } from '../../../signer';

describe('KeylessSigner', () => {
  const fulcioBaseURL = 'http://localhost:8080';
  const signature = 'signature';
  const publicKey = 'publickey';

  const keyHolder: Signer = {
    sign: () =>
      Promise.resolve({
        signature: Buffer.from('signature'),
        key: { $case: 'publicKey', publicKey },
      }),
  };

  const options: FulcioSignerOptions = {
    fulcioBaseURL,
    identityProvider: { getToken: jest.fn() },
    keyHolder: keyHolder,
  };

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new FulcioSigner({ ...options, keyHolder: undefined });
      expect(client).toBeDefined();
    });
  });

  describe('sign', () => {
    // Data to be signed
    const payload = Buffer.from('Hello, world!');

    // JWT to be returned by the identity provider
    const jwtPayload = {
      iss: 'https://example.com',
      sub: 'foo@bar.com',
    };
    const jwt = `.${Buffer.from(JSON.stringify(jwtPayload)).toString(
      'base64'
    )}.`;

    // Mock identity provider returns a JWT
    const tokenProvider: IdentityProvider = {
      getToken: jest.fn().mockResolvedValue(jwt),
    };

    const subject = new FulcioSigner({
      ...options,
      identityProvider: tokenProvider,
    });

    describe('when the identity provider returns an error', () => {
      const errorProvider: IdentityProvider = {
        getToken: jest.fn().mockRejectedValue(new Error('oops')),
      };

      const subject = new FulcioSigner({
        ...options,
        identityProvider: errorProvider,
      });

      it('throws an error', async () => {
        await expect(subject.sign(payload)).rejects.toThrowWithCode(
          InternalError,
          'IDENTITY_TOKEN_READ_ERROR'
        );
      });
    });

    describe('when the identity provider returns an invalid token', () => {
      const errorProvider: IdentityProvider = {
        getToken: jest.fn().mockResolvedValue(''),
      };

      const subject = new FulcioSigner({
        ...options,
        identityProvider: errorProvider,
      });

      it('throws an error', async () => {
        await expect(subject.sign(payload)).rejects.toThrowWithCode(
          InternalError,
          'IDENTITY_TOKEN_PARSE_ERROR'
        );
      });
    });

    describe('when the child signer returns an invalid key', () => {
      const keyHolder: Signer = {
        sign: () =>
          Promise.resolve({
            signature: Buffer.from('signature'),
            key: { $case: 'x509Certificate', certificate: 'cert' },
          }),
      };

      const subject = new FulcioSigner({
        ...options,
        identityProvider: tokenProvider,
        keyHolder: keyHolder,
      });

      it('throws an error', async () => {
        await expect(subject.sign(payload)).rejects.toThrowWithCode(
          InternalError,
          'CA_CREATE_SIGNING_CERTIFICATE_ERROR'
        );
      });
    });

    describe('when Fulcio returns a valid response', () => {
      // Fulcio output
      const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----`;
      const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----`;

      // Expected Fulcio request
      const expctedRequest = {
        credentials: {
          oidcIdentityToken: jwt,
        },
        publicKeyRequest: {
          publicKey: {
            algorithm: 'ECDSA',
            content: publicKey,
          },
          proofOfPossession: Buffer.from(signature).toString('base64'),
        },
      };

      beforeEach(() => {
        nock(fulcioBaseURL)
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v2/signingCert', expctedRequest)
          .reply(200, {
            signedCertificateEmbeddedSct: {
              chain: { certificates: [leafCertificate, rootCertificate] },
            },
          });
      });

      it('returns a signature', async () => {
        const result = await subject.sign(payload);

        expect(result).toBeTruthy();
        expect(result.signature).toBeTruthy();
        assert(result.key.$case === 'x509Certificate');
        expect(result.key.certificate).toEqual(leafCertificate);
      });
    });

    describe('when Fulcio returns an invalid response', () => {
      beforeEach(() => {
        nock(fulcioBaseURL)
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v2/signingCert')
          .reply(500, {});
      });

      it('throws an error', async () => {
        try {
          await subject.sign(payload);
          throw new Error('Expected an error to be thrown');
        } catch (e) {
          assert(e instanceof InternalError);
          expect(e.code).toEqual('CA_CREATE_SIGNING_CERTIFICATE_ERROR');
        }
      });
    });
  });
});
