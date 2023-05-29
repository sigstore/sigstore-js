import nock from 'nock';
import type { Handler, HandlerFn } from './shared.types';

type NockHandler = (
  uri: string,
  request: nock.Body
) => Promise<nock.ReplyFnResult>;

// Sets-up nock-based mocking for the given handler
export function mock(base: string, handler: Handler): void {
  nock(base).post(handler.path).reply(adapt(handler.fn));
}

// Adapts our HandlerFn to nock's NockHandler format
function adapt(handler: HandlerFn): NockHandler {
  return async (_: string, body: nock.Body): Promise<nock.ReplyFnResult> => {
    const req = typeof body === 'string' ? body : JSON.stringify(body);
    return handler(req).then(({ statusCode, response, contentType }) => [
      statusCode,
      response,
      { 'Content-Type': contentType || 'text/plain' },
    ]);
  };
}
