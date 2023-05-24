import fetch from 'make-fetch-happen';
import { URLSearchParams } from 'url';
import { CallbackServer } from '../../oauth/server';

describe('CallbackServer', () => {
  const opts = {
    port: 8989,
    hostname: 'localhost',
  };

  describe('constructor', () => {
    it('should create a new CallbackServer', () => {
      const server = new CallbackServer(opts);
      expect(server).toBeDefined();
    });
  });

  describe('start', () => {
    const server = new CallbackServer(opts);

    afterEach(async () => {
      await server.shutdown();
    });

    it('return the server URL', async () => {
      const url = await server.start();
      expect(url).toMatch(/http:\/\/localhost:\d+/);
    });
  });

  describe('callback', () => {
    const server = new CallbackServer(opts);

    afterEach(async () => {
      await server.shutdown();
    });

    it('should resolve when the server receives a request', async () => {
      const url = await server.start();

      // Simulate a user being redirect to the callback URL
      const params = new URLSearchParams({
        code: '123',
        state: 'abc',
      });
      const callbackURL = `${url}/callback?${params.toString()}`;
      await fetch(callbackURL);

      const result = await server.callback;
      expect(result).toEqual(`/callback?${params.toString()}`);
    });
  });
});
