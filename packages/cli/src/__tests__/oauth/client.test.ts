import * as jose from 'jose';
import nock from 'nock';
import { initializeOAuthClient } from '../../oauth/client';

describe('OAuthClient', () => {
  const issuer = 'http://foo.com/auth';
  const opts = {
    issuer,
    redirectURL: 'http://foo.com',
    clientID: 'sigstore',
  };

  const wellKnownResponse = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/keys`,
  };

  beforeEach(() => {
    nock(issuer)
      .get('/.well-known/openid-configuration')
      .reply(200, wellKnownResponse);
  });

  describe('initializeOAuthClient', () => {
    it('should return a client', async () => {
      const client = await initializeOAuthClient(opts);
      expect(client).toBeDefined();
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
  });

  describe('getIDToken', () => {
    it('should bar', async () => {
      const options = { ...opts, clientSecret: 'foo' };
      const client = await initializeOAuthClient(options);

      const url = new URL(client.authorizationUrl);
      const state = url.searchParams.get('state');
      const nonce = url.searchParams.get('nonce');
      const callbackURL = `http://localhost:8080/callback?code=123&state=${state}`;

      // Provision a verifiable JWT
      const { privateKey, publicKey } = await jose.generateKeyPair('RS256');
      const jwk = await jose.exportJWK(publicKey);
      const jwt = await new jose.SignJWT({ nonce })
        .setAudience('sigstore')
        .setSubject('foo@bar.com')
        .setIssuer(issuer)
        .setIssuedAt()
        .setExpirationTime('1h')
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);

      nock(issuer)
        .post('/token')
        .basicAuth({ user: options.clientID, pass: options.clientSecret })
        .reply(200, { id_token: jwt });
      nock(issuer)
        .get('/keys')
        .reply(200, { keys: [jwk] });

      const idToken = await client.getIDToken(callbackURL);
      expect(idToken).toEqual(jwt);
    });
  });
});
