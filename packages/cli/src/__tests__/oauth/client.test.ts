import * as jose from 'jose';
import { createHash } from 'node:crypto';
import { initializeOAuthClient } from '../../oauth/client';

describe('OAuthClient', () => {
  const issuer = 'https://foo.com/auth';
  const opts = {
    issuer,
    redirectURL: 'http://localhost:8080/callback',
    clientID: 'sigstore',
  };

  const wellKnownResponse = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/keys`,
  };

  let mockedFetch: jest.SpiedFunction<typeof fetch>;

  beforeEach(() => {
    mockedFetch = jest
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('unexpected fetch request'))
      .mockResolvedValueOnce(Response.json(wellKnownResponse));
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('initializeOAuthClient', () => {
    it('should return a client', async () => {
      const client = await initializeOAuthClient(opts);
      expect(client).toBeDefined();
      expect(mockedFetch.mock.calls[0][0].toString()).toEqual(
        `${issuer}/.well-known/openid-configuration`
      );
    });

    it('propagates discovery errors', async () => {
      mockedFetch.mockReset().mockRejectedValueOnce(new Error('offline'));
      await expect(initializeOAuthClient(opts)).rejects.toThrow();
    });

    it('rejects insecure issuers', async () => {
      await expect(
        initializeOAuthClient({ ...opts, issuer: 'http://foo.com/auth' })
      ).rejects.toThrow();
    });
  });

  describe('#authorizationUrl', () => {
    it('should return a client with the correct issuer', async () => {
      const client = await initializeOAuthClient(opts);

      const url = new URL(client.authorizationUrl);
      expect(url.hostname).toEqual('foo.com');
      expect(url.pathname).toEqual('/auth/authorize');
      expect(url.searchParams.get('client_id')).toEqual(opts.clientID);
      expect(url.searchParams.get('scope')).toEqual('openid email');
      expect(url.searchParams.get('response_type')).toEqual('code');
      expect(url.searchParams.get('redirect_uri')).toEqual(opts.redirectURL);
      expect(url.searchParams.get('code_challenge')).toBeTruthy();
      expect(url.searchParams.get('code_challenge_method')).toEqual('S256');
      expect(url.searchParams.get('nonce')).toBeTruthy();
      expect(url.searchParams.get('state')).toBeTruthy();
    });

    it('uses stable parameters within a flow and fresh parameters for each flow', async () => {
      const first = await initializeOAuthClient(opts);
      mockedFetch.mockResolvedValueOnce(Response.json(wellKnownResponse));
      const second = await initializeOAuthClient(opts);

      expect(first.authorizationUrl).toEqual(first.authorizationUrl);
      const firstURL = new URL(first.authorizationUrl);
      const secondURL = new URL(second.authorizationUrl);
      for (const parameter of ['code_challenge', 'state', 'nonce']) {
        expect(firstURL.searchParams.get(parameter)).not.toEqual(
          secondURL.searchParams.get(parameter)
        );
      }
    });
  });

  describe('getIDToken', () => {
    it.each([undefined, 'foo'])(
      'exchanges a code with client secret %s and sends the PKCE verifier',
      async (clientSecret) => {
        const client = await initializeOAuthClient({ ...opts, clientSecret });
        const url = new URL(client.authorizationUrl);
        const jwt = await mockTokenResponse(url);
        const callbackURL = `${opts.redirectURL}?code=123&state=${url.searchParams.get('state')}`;

        await expect(client.getIDToken(callbackURL)).resolves.toEqual(jwt);

        const [tokenURL, request] = mockedFetch.mock.calls[1];
        expect(tokenURL.toString()).toEqual(`${issuer}/token`);
        expect(request?.method).toEqual('POST');
        const body = new URLSearchParams(request?.body?.toString());
        expect(body.get('grant_type')).toEqual('authorization_code');
        expect(body.get('code')).toEqual('123');
        expect(body.get('redirect_uri')).toEqual(opts.redirectURL);
        expect(body.has('client_secret')).toBe(false);
        const verifier = body.get('code_verifier')!;
        expect(verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
        expect(
          createHash('sha256').update(verifier).digest('base64url')
        ).toEqual(url.searchParams.get('code_challenge'));
        const headers = new Headers(request?.headers);
        if (clientSecret) {
          expect(headers.get('authorization')).toEqual(
            `Basic ${Buffer.from(`${opts.clientID}:${clientSecret}`).toString('base64')}`
          );
        } else {
          expect(headers.has('authorization')).toBe(false);
          expect(body.get('client_id')).toEqual(opts.clientID);
        }
        expect(mockedFetch.mock.calls[2][0].toString()).toEqual(
          `${issuer}/keys`
        );
      }
    );

    it('accepts a relative callback URL from the callback server', async () => {
      const client = await initializeOAuthClient(opts);
      const url = new URL(client.authorizationUrl);
      const jwt = await mockTokenResponse(url);
      await expect(
        client.getIDToken(
          `/callback?code=123&state=${url.searchParams.get('state')}`
        )
      ).resolves.toEqual(jwt);
    });

    it('uses the same redirect URI at both endpoints for a bare localhost origin', async () => {
      const client = await initializeOAuthClient({
        ...opts,
        redirectURL: 'http://localhost:8080',
      });
      const url = new URL(client.authorizationUrl);
      await mockTokenResponse(url);
      await client.getIDToken(`/?code=123&state=${url.searchParams.get('state')}`);

      const body = new URLSearchParams(
        mockedFetch.mock.calls[1][1]?.body?.toString()
      );
      expect(body.get('redirect_uri')).toEqual(
        url.searchParams.get('redirect_uri')
      );
    });

    it.each(['wrong', ''])(
      'rejects invalid state %s before exchanging the code',
      async (state) => {
        const client = await initializeOAuthClient(opts);
        await expect(
          client.getIDToken(`${opts.redirectURL}?code=123&state=${state}`)
        ).rejects.toThrow();
        expect(mockedFetch).toHaveBeenCalledTimes(1);
      }
    );

    it.each([
      { nonce: 'wrong' },
      { aud: 'wrong' },
      { iss: 'https://wrong.example' },
      { exp: 0 },
    ])('rejects invalid ID token claims %j', async (claims) => {
      const client = await initializeOAuthClient(opts);
      const url = new URL(client.authorizationUrl);
      await mockTokenResponse(url, claims);
      await expect(
        client.getIDToken(
          `${opts.redirectURL}?code=123&state=${url.searchParams.get('state')}`
        )
      ).rejects.toThrow();
    });

    it('rejects an ID token signed with a different key', async () => {
      const client = await initializeOAuthClient(opts);
      const url = new URL(client.authorizationUrl);
      await mockTokenResponse(url, {}, true);
      await expect(
        client.getIDToken(
          `${opts.redirectURL}?code=123&state=${url.searchParams.get('state')}`
        )
      ).rejects.toThrow();
    });

    it('requires an ID token in the response', async () => {
      const client = await initializeOAuthClient(opts);
      const url = new URL(client.authorizationUrl);
      mockedFetch.mockResolvedValueOnce(
        Response.json({ access_token: 'access-token', token_type: 'Bearer' })
      );
      await expect(
        client.getIDToken(
          `${opts.redirectURL}?code=123&state=${url.searchParams.get('state')}`
        )
      ).rejects.toThrow();
    });

    it('propagates authorization errors without exchanging a code', async () => {
      const client = await initializeOAuthClient(opts);
      const url = new URL(client.authorizationUrl);
      await expect(
        client.getIDToken(
          `${opts.redirectURL}?error=access_denied&state=${url.searchParams.get('state')}`
        )
      ).rejects.toThrow();
      expect(mockedFetch).toHaveBeenCalledTimes(1);
    });
  });

  async function mockTokenResponse(
    authorizationURL: URL,
    claims: jose.JWTPayload = {},
    invalidSignature = false
  ): Promise<string> {
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256');
    const jwk = await jose.exportJWK(publicKey);
    const signingKey = invalidSignature
      ? (await jose.generateKeyPair('RS256')).privateKey
      : privateKey;
    const jwt = await new jose.SignJWT({
      nonce: authorizationURL.searchParams.get('nonce'),
      aud: opts.clientID,
      sub: 'foo@bar.com',
      iss: issuer,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      ...claims,
    })
      .setProtectedHeader({ alg: 'RS256' })
      .sign(signingKey);

    mockedFetch
      .mockResolvedValueOnce(
        Response.json({
          access_token: 'access-token',
          token_type: 'Bearer',
          id_token: jwt,
        })
      )
      .mockResolvedValueOnce(Response.json({ keys: [jwk] }));
    return jwt;
  }
});
