 import * as jose from 'jose';
import fetch from 'make-fetch-happen';
import nock from 'nock';
import open from 'open';
import { OAuthIdentityProvider } from '../../oauth';

import type { ChildProcess } from 'child_process';

jest.mock('open', () => jest.fn());
const mockedOpen = jest.mocked(open);

describe('OAuthIdentityProvider', () => {
  describe('constructor', () => {
    it('creates a new OAuthIdentityProvider', () => {
      const provider = new OAuthIdentityProvider({
        issuer: 'https://oauth2.sigstore.dev/auth',
        clientID: 'sigstore',
        clientSecret: 'secret',
        redirectURL: 'http://localhost:8080/callback',
      });

      expect(provider).toBeDefined();
    });

    describe('#getToken', () => {
      const issuer = 'http://foo.com/auth';
      const subject = 'foo@bar.com';
      const opts = {
        issuer,
        clientID: 'sigstore',
      };

      mockedOpen.mockImplementation(sendFakeRedirect(issuer, subject));

      const wellKnownResponse = {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/keys`,
      };

      nock(issuer)
        .get('/.well-known/openid-configuration')
        .reply(200, wellKnownResponse);

      it('should return a token', async () => {
        const provider = new OAuthIdentityProvider(opts);
        const idToken = await provider.getToken();

        const claims = jose.decodeJwt(idToken);
        expect(claims.aud).toEqual(opts.clientID);
        expect(claims.iss).toEqual(issuer);
        expect(claims.sub).toEqual(subject);
      });
    });
  });
});

function sendFakeRedirect(issuer: string, subject: string) {
  // Simulate a user being redirect to the callback URL
  return async (authURL: string): ReturnType<typeof open> => {
    // Extract data from the auth URL so that we can construct the callback URL
    // and construct and verifiable JWT to be returned by the token endpoint.
    const url = new URL(authURL);
    const state = url.searchParams.get('state') || '';
    const nonce = url.searchParams.get('nonce');
    const clientID = url.searchParams.get('client_id')!;
    const redirectURL = url.searchParams.get('redirect_uri');

    // Provision a verifiable JWT
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256');
    const jwk = await jose.exportJWK(publicKey);
    const jwt = await new jose.SignJWT({ nonce })
      .setAudience(clientID)
      .setSubject(subject)
      .setIssuer(issuer)
      .setIssuedAt()
      .setExpirationTime('1h')
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);

    nock(issuer).post('/token').reply(200, { id_token: jwt });
    nock(issuer)
      .get('/keys')
      .reply(200, { keys: [jwk] });

    // Construct the callback URL
    const params = new URLSearchParams({
      code: 'abc123',
      state: state,
    });
    const callbackURL = `${redirectURL}?${params.toString()}`;

    return fetch(callbackURL).then(() => {
      return {} as ChildProcess;
    });
  };
}
