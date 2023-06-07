/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
  /* istanbul ignore next */
  return async (_: string, body: nock.Body): Promise<nock.ReplyFnResult> => {
    const req = typeof body === 'string' ? body : JSON.stringify(body);
    return handler(req).then(({ statusCode, response, contentType }) => [
      statusCode,
      response,
      { 'Content-Type': contentType || 'text/plain' },
    ]);
  };
}
