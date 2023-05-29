import { generateKeyPairSync } from 'crypto';
import { CA, initializeCA } from './ca';
import { fulcioHandler } from './handler';

describe('fulcioHandler', () => {
  describe('#path', () => {
    it('returns the correct path', async () => {
      const ca = await initializeCA();
      const handler = fulcioHandler(ca);
      expect(handler.path).toBe('/api/v2/signingCert');
    });
  });

  describe('#fn', () => {
    it('returns a function', async () => {
      const ca = await initializeCA();
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
        const ca = await initializeCA();
        const { fn } = fulcioHandler(ca);

        // Make a request
        const resp = await fn(JSON.stringify(certRequest));
        expect(resp.statusCode).toBe(201);

        // Check the response
        const certs = JSON.parse(resp.response);
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

function jwtify(obj: any): string {
  return `.${Buffer.from(JSON.stringify(obj)).toString('base64')}.`;
}
