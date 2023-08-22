import assert from 'assert';
import { internalError, InternalError } from '../error';
import { HTTPError } from '../external/error';

describe('internalError', () => {
  const code = 'IDENTITY_TOKEN_READ_ERROR';

  describe('when err is an Error', () => {
    const err = new Error('oops');
    const msg = 'test error';

    it('throws an InternalError', () => {
      expect.assertions(4);
      try {
        internalError(err, code, msg);
      } catch (e) {
        assert(e instanceof InternalError);
        expect(e.message).toEqual(msg);
        expect(e.code).toEqual(code);
        expect(e.cause).toEqual(err);
        expect(e.name).toEqual('InternalError');
      }
    });
  });

  describe('when err is an HTTPError', () => {
    const err = new HTTPError({ status: 404, message: 'oops' });
    const msg = 'test error';

    it('throws an InternalError', () => {
      expect.assertions(4);
      try {
        internalError(err, code, msg);
      } catch (e) {
        assert(e instanceof InternalError);
        expect(e.message).toEqual(`${msg} - ${err.message}`);
        expect(e.code).toEqual(code);
        expect(e.cause).toEqual(err);
        expect(e.name).toEqual('InternalError');
      }
    });
  });
});
