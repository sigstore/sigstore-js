import nock from 'nock';
import { default as ciContextProvider } from './ci';

describe('ciContextProvider', () => {
  it('should exist', () => {
    expect(ciContextProvider).toBeTruthy();
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
        const token = await ciContextProvider.getToken();
        expect(token).toBe(oidcToken);
      });
    });

    describe('when the GHA environment variables are NOT set', () => {
      it('returns undefined', async () => {
        const token = await ciContextProvider.getToken();
        expect(token).toBeUndefined();
      });
    });
  });
});
