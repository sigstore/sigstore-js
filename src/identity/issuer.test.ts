import nock from 'nock';
import { Issuer } from './issuer';

describe('Issuer', () => {
  const baseURL = 'http://localhost:8080';
  const subject = new Issuer(baseURL);

  const openIDConfig = {
    authorization_endpoint: 'auth',
    token_endpoint: 'token',
  };

  beforeEach(() => {
    nock.cleanAll();
    nock(baseURL)
      .get('/.well-known/openid-configuration')
      .once()
      .reply(200, openIDConfig);
  });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#authEndpoint', () => {
    it('returns the auth endpoint', async () => {
      const endpoint = await subject.authEndpoint();
      expect(endpoint).toBe(openIDConfig.authorization_endpoint);
    });

    it('only fetches the endpoint once', async () => {
      await subject.authEndpoint();
      const endpoint = await subject.authEndpoint();
      expect(endpoint).toBe(openIDConfig.authorization_endpoint);
    });
  });

  describe('#tokenEndpoint', () => {
    it('returns the token endpoint', async () => {
      const endpoint = await subject.tokenEndpoint();
      expect(endpoint).toBe(openIDConfig.token_endpoint);
    });

    it('only fetches the endpoint once', async () => {
      await subject.tokenEndpoint();
      const endpoint = await subject.tokenEndpoint();
      expect(endpoint).toBe(openIDConfig.token_endpoint);
    });
  });
});
