import fetch from 'make-fetch-happen';
import { checkStatus } from './error';

type Response = Awaited<ReturnType<typeof fetch>>;

describe('checkStatus', () => {
  describe('when the response is OK', () => {
    const response: Response = {
      status: 200,
      statusText: 'OK',
      ok: true,
    } as Response;

    it('returns the response', () => {
      expect(checkStatus(response)).toEqual<Response>(response);
    });
  });

  describe('when the response is not OK', () => {
    const response: Response = {
      status: 404,
      statusText: 'Not Found',
      ok: false,
    } as Response;

    it('throws an error', () => {
      expect(() => checkStatus(response)).toThrow('HTTP Error: 404 Not Found');
    });
  });
});
