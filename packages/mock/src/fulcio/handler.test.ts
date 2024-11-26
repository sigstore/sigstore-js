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

import { Crypto } from '@peculiar/webcrypto';
import x509 from '@peculiar/x509';
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
    const claims = {
      sub: 'http://github.com/foo/workflow.yml@refs/heads/main',
      iss: 'http://foo.com',
      event_name: 'workflow_dispatch',
      job_workflow_ref:
        'foo/attest-demo/.github/workflows/oidc.yml@refs/heads/main',
      job_workflow_sha: 'ba214227977e57973d87219493ad93eeda9c7d6c',
      ref: 'refs/heads/main',
      repository: 'foo/attest-demo',
      repository_id: '792829709',
      repository_owner: 'foo',
      repository_owner_id: '398027',
      repository_visibility: 'public',
      run_attempt: '3',
      run_id: '11997537386',
      runner_environment: 'github-hosted',
      sha: 'ba214227977e57973d87219493ad93eeda9c7d6c',
      workflow: 'OIDC',
      workflow_ref:
        'foo/attest-demo/.github/workflows/oidc.yml@refs/heads/main',
      workflow_sha: 'ba214227977e57973d87219493ad93eeda9c7d6c',
    };
    const jwt = jwtify(claims);

    it('returns a function', async () => {
      const ca = await initializeCA(keyPair);
      const handler = fulcioHandler(ca);
      expect(handler.fn).toBeInstanceOf(Function);
    });

    describe('when invoked w/ a public key', () => {
      const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

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

        const { extensions, publicKey } = new x509.X509Certificate(
          certs.signedCertificateEmbeddedSct.chain.certificates[0]
        );

        // Ensure public key matches input
        expect(publicKey.toString('pem')).toEqual(
          certRequest.publicKeyRequest.publicKey.content.trimEnd()
        );
        expect(
          extensions
            .filter((e) => e.type.startsWith('1.3.6.1.4.1.57264'))
            .map((e) => e.toString('asn'))
        ).toMatchSnapshot();
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

    describe('when invoked w/ a CSR', () => {
      it('returns a certificate chain', async () => {
        const crypto = new Crypto();
        const kp = await crypto.subtle.generateKey(
          { name: 'ecdsa', namedCurve: 'P-256' },
          true,
          ['sign', 'verify']
        );
        const csr = await x509.Pkcs10CertificateRequestGenerator.create(
          {
            signingAlgorithm: {
              name: 'ECDSA',
              hash: 'SHA-256',
            },
            keys: kp,
          },
          crypto
        );

        const certRequest = {
          credentials: {
            oidcIdentityToken: jwt,
          },
          certificateSigningRequest: csr.toString('pem'),
        };

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

        const { extensions, publicKey } = new x509.X509Certificate(
          certs.signedCertificateEmbeddedSct.chain.certificates[0]
        );

        // Ensure public key matches the CSR
        const expectedKey = await crypto.subtle.exportKey('spki', kp.publicKey);
        expect(publicKey.toString('base64')).toEqual(
          Buffer.from(expectedKey).toString('base64')
        );

        expect(
          extensions
            .filter((e) => e.type.startsWith('1.3.6.1.4.1.57264'))
            .map((e) => e.toString('asn'))
        ).toMatchSnapshot();
      });
    });
  });
});

/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
function jwtify(obj: any): string {
  return `.${Buffer.from(JSON.stringify(obj)).toString('base64')}.`;
}
