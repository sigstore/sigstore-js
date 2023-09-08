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

import { generateKeyPairSync } from 'crypto';
import { generateKeyPair } from '../util/key';
import { CA, initializeCA } from './ca';
import { fulcioHandler } from './handler';

describe('fulcioHandler', () => {
  const keyPair = generateKeyPair('prime256v1');

  describe('#path', () => {
    it('returns the correct path', async () => {
      const ca = await initializeCA(keyPair);
      const handler = fulcioHandler(ca);
      expect(handler.path).toBe('/api/v2/signingCert');
    });
  });

  describe('#fn', () => {
    it('returns a function', async () => {
      const ca = await initializeCA(keyPair);
      const handler = fulcioHandler(ca);
      expect(handler.fn).toBeInstanceOf(Function);
    });

    describe('when invoked', () => {
      const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

      const claims = {
        sub: 'http://github.com/foo/workflow.yml@refs/heads/main',
      };
      const jwt = jwtify(claims);

      const certRequest = {
        credentials: {
          oidcIdentityToken: jwt,
        },
        publicKeyRequest: {
          publicKey: {
            algorithm: 'ECDSA',
            content: publicKey
              .export({ format: 'pem', type: 'spki' })
              .toString('ascii'),
          },
          proofOfPossession: 'foobar',
        },
      };

      it('returns a certificate chain', async () => {
        const ca = await initializeCA(keyPair);
        const { fn } = fulcioHandler(ca);

        // Make a request
        const resp = await fn(JSON.stringify(certRequest));
        expect(resp.statusCode).toBe(201);

        // Check the response
        const certs = JSON.parse(resp.response.toString());
        expect(certs).toBeDefined();
        expect(certs.signedCertificateEmbeddedSct).toBeDefined();
        expect(certs.signedCertificateEmbeddedSct.chain).toBeDefined();
        expect(
          certs.signedCertificateEmbeddedSct.chain.certificates
        ).toBeDefined();
        expect(
          certs.signedCertificateEmbeddedSct.chain.certificates
        ).toHaveLength(2);
      });

      describe('when the CA raises an error', () => {
        const ca: CA = {
          rootCertificate: Buffer.from(''),
          issueCertificate: async () => {
            throw new Error('oops');
          },
        };

        it('returns 400 error', async () => {
          const { fn } = fulcioHandler(ca, { strict: false });
          const resp = await fn(JSON.stringify(certRequest));
          expect(resp.statusCode).toBe(400);
        });
      });
    });
  });
});

/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
function jwtify(obj: any): string {
  return `.${Buffer.from(JSON.stringify(obj)).toString('base64')}.`;
}
