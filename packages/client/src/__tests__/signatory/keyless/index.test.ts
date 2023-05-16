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
import {
  KeylessSigner,
  KeylessSignerOptions,
} from '../../../signatory/keyless';

import type { Provider } from '../../../identity';

describe('KeylessSigner', () => {
  const fulcioBaseURL = 'http://localhost:8080';

  const options: KeylessSignerOptions = {
    fulcioBaseURL,
    identityProviders: [],
  };

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new KeylessSigner(options);
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
    const tokenProvider: Provider = {
      getToken: jest.fn().mockResolvedValue(jwt),
    };

    const subject = new KeylessSigner({
      ...options,
      identityProviders: [tokenProvider],
    });

    describe('when no identity providers are configured', () => {
      const subject = new KeylessSigner(options);

      it('throws an error', async () => {
        try {
          await subject.sign(payload);
          throw new Error('Expected an error to be thrown');
        } catch (e) {
          assert(e instanceof InternalError);
          expect(e.code).toEqual('IDENTITY_TOKEN_READ_ERROR');
        }
      });
    });

    describe('when the identity provider returns an error', () => {
      const errorProvider: Provider = {
        getToken: jest.fn().mockRejectedValue(new Error('oops')),
      };

      const subject = new KeylessSigner({
        ...options,
        identityProviders: [errorProvider],
      });

      it('throws an error', async () => {
        try {
          await subject.sign(payload);
          throw new Error('Expected an error to be thrown');
        } catch (e) {
          assert(e instanceof InternalError);
          expect(e.code).toEqual('IDENTITY_TOKEN_READ_ERROR');
        }
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
            content: /.+/i,
          },
          proofOfPossession: /.+/i,
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

      it('returns an endorsement', async () => {
        const result = await subject.sign(payload);

        expect(result).toBeTruthy();
        expect(result.signature).toBeTruthy();
        assert(result.key.$case === 'x509Certificate');
        expect(result.key.certificate).toEqual;
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
