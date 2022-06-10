import nock from 'nock';
import { Sigstore } from './sigstore';

describe('Sigstore', () => {
  const fulcioBaseURL = 'http://localhost:8001';
  const rekorBaseURL = 'http://localhost:8002';
  const subject = new Sigstore({ fulcioBaseURL, rekorBaseURL });

  const jwtPayload = {
    iss: 'https://example.com',
    sub: 'foo@bar.com',
  };
  const jwt = `.${Buffer.from(JSON.stringify(jwtPayload)).toString('base64')}.`;

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#signDSSE', () => {
    const payload = Buffer.from('Hello, world!');
    const payloadType = 'http://example.com/HelloWorld';

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

    describe('when something', () => {
      const rekorEntry = { a12bc3: {} };

      beforeEach(() => {
        // Mock Rekor request
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries')
          .reply(201, rekorEntry);
      });

      it('returns a DSSE object', async () => {
        const dsse = await subject.signDSSE(payload, payloadType, jwt);

        expect(dsse).toBeTruthy();
        expect(dsse.payload).toEqual(payload.toString('base64'));
        expect(dsse.payloadType).toEqual(payloadType);
        expect(dsse.signatures).toHaveLength(1);
      });
    });
  });
});
