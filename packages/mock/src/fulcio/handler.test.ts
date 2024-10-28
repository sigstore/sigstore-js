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

import { generateKeyPairSync, subtle } from 'crypto';
import { generateKeyPair } from '../util/key';
import { CA, initializeCA } from './ca';
import { fulcioHandler } from './handler';
import x509 from '@peculiar/x509';

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
        iss: 'http://foo.com',
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

      it('errors when given both csr and pkr', async () => {
        const ca = await initializeCA(keyPair);
        const { fn } = fulcioHandler(ca);

        const req = {
          ...certRequest,
          certificateSigningRequest: {},
        };
        const resp = await fn(JSON.stringify(req));
        expect(resp.statusCode).toBe(400);
        expect(resp.response.toString()).toEqual(
          'Invalid request -- cannot specify both CSR and public key'
        );
      });

      it('errors when missing both csr and pkr', async () => {
        const ca = await initializeCA(keyPair);
        const { fn } = fulcioHandler(ca);

        const resp = await fn(JSON.stringify({}));
        expect(resp.statusCode).toBe(400);
        expect(resp.response.toString()).toEqual(
          'Invalid request -- must specify either CSR or public key'
        );
      });

      it('errors when missing oidcIdentityToken', async () => {
        const ca = await initializeCA(keyPair);
        const { fn } = fulcioHandler(ca);

        const resp = await fn(
          JSON.stringify({
            ...certRequest,
            credentials: {},
          })
        );
        expect(resp.statusCode).toBe(400);
        expect(resp.response.toString()).toEqual(
          'Invalid request -- missing OIDC identity token'
        );
      });

      it('returns a certificate with github extension', async () => {
        const kp2 = await subtle.generateKey(
          { name: 'ecdsa', namedCurve: 'P-256' },
          true,
          ['sign', 'verify']
        );
        const csr = await x509.Pkcs10CertificateRequestGenerator.create({
          signingAlgorithm: {
            name: 'ECDSA',
            hash: 'SHA-256',
          },
          keys: kp2,
        });

        const claims = {
          jti: '1fa628c1-c044-482b-a350-0efe250f852b',
          sub: 'repo:sigstore-conformance/extremely-dangerous-public-oidc-beacon:ref:refs/heads/main',
          aud: 'sigstore',
          ref: 'refs/heads/main',
          sha: '82a3bfe6dd50fe9c71d6315eae66da15307856cf',
          repository:
            'sigstore-conformance/extremely-dangerous-public-oidc-beacon',
          repository_owner: 'sigstore-conformance',
          repository_owner_id: '131804563',
          run_id: '11566574533',
          run_number: '171745',
          run_attempt: '1',
          repository_visibility: 'public',
          repository_id: '632596897',
          actor_id: '41898282',
          actor: 'github-actions[bot]',
          workflow: 'Extremely dangerous OIDC beacon',
          head_ref: '',
          base_ref: '',
          event_name: 'workflow_dispatch',
          ref_protected: 'true',
          ref_type: 'branch',
          workflow_ref:
            'sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main',
          workflow_sha: '82a3bfe6dd50fe9c71d6315eae66da15307856cf',
          job_workflow_ref:
            'sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main',
          job_workflow_sha: '82a3bfe6dd50fe9c71d6315eae66da15307856cf',
          runner_environment: 'github-hosted',
          iss: 'https://token.actions.githubusercontent.com',
          nbf: 1730170833,
          exp: 1730171733,
          iat: 1730171433,
        };
        const jwt = jwtify(claims);

        const certRequest = {
          credentials: {
            oidcIdentityToken: jwt,
          },
          certificateSigningRequest: csr.toString(),
        };

        const ca = await initializeCA(keyPair);
        const { fn } = fulcioHandler(ca);

        // Make a request
        const resp = await fn(JSON.stringify(certRequest));
        expect(resp.statusCode).toBe(201);

        const certs = JSON.parse(resp.response.toString());
        expect(certs).toBeDefined();
        expect(certs.signedCertificateEmbeddedSct).toBeDefined();
        expect(certs.signedCertificateEmbeddedSct.chain).toBeDefined();
        expect(
          certs.signedCertificateEmbeddedSct.chain.certificates
        ).toBeDefined();

        const { extensions } = new x509.X509Certificate(
          certs.signedCertificateEmbeddedSct.chain.certificates[0]
        );
        expect(
          extensions
            .filter((e) => e.type !== '2.5.29.14')
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
