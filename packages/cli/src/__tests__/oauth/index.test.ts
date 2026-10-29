import * as jose from 'jose';
import open from 'open';
import { OAuthIdentityProvider } from '../../oauth';

import type { ChildProcess } from 'child_process';

jest.mock('open', () => jest.fn());
const mockedOpen = jest.mocked(open);
const fetchCallback = globalThis.fetch;

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
      const issuer = 'https://foo.com/auth';
      const subject = 'foo@bar.com';
      const opts = {
        issuer,
        clientID: 'sigstore',
      };

      const wellKnownResponse = {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/keys`,
      };

      beforeEach(() => {
        const mockedFetch = jest
          .spyOn(globalThis, 'fetch')
          .mockRejectedValue(new Error('unexpected fetch request'))
          .mockResolvedValueOnce(Response.json(wellKnownResponse));
        mockedOpen.mockImplementation(
          sendFakeRedirect(issuer, subject, mockedFetch)
        );
      });

      afterEach(() => {
        jest.restoreAllMocks();
      });

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

function sendFakeRedirect(
  issuer: string,
  subject: string,
  mockedFetch: jest.SpiedFunction<typeof fetch>
) {
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

    mockedFetch
      .mockResolvedValueOnce(
        Response.json({
          access_token: 'access-token',
          token_type: 'Bearer',
          id_token: jwt,
        })
      )
      .mockResolvedValueOnce(Response.json({ keys: [jwk] }));

    // Construct the callback URL
    const params = new URLSearchParams({
      code: 'abc123',
      state: state,
    });
    const callbackURL = `${redirectURL}?${params.toString()}`;

    return fetchCallback(callbackURL).then(() => {
      return {} as ChildProcess;
    });
  };
}
