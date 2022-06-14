import nock from 'nock';
import { GHAProvider } from './gha';

describe('GHAProvider', () => {
  const subject = new GHAProvider();

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#getToken', () => {
    describe('when the GHA environment variables are set', () => {
      const requestURL = 'http://localhost:8080';
      const requestToken = 'abc123';

      const oidcToken = 'x.y.z';

      beforeEach(() => {
        process.env.ACTIONS_ID_TOKEN_REQUEST_URL = requestURL;
        process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = requestToken;

        nock(requestURL)
          .get('/')
          .query({ audience: 'sigstore' })
          .reply(200, { value: oidcToken });
      });

      afterEach(() => {
        delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
        delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
      });

      it('returns the token', async () => {
        const token = await subject.getToken();
        expect(token).toBe(oidcToken);
      });
    });

    describe('when the GHA environment variables are NOT set', () => {
      it('returns undefined', async () => {
        const token = await subject.getToken();
        expect(token).toBeUndefined();
      });
    });
  });
});
