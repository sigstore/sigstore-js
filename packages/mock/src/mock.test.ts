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

import fetch from 'make-fetch-happen';
import { mock } from './mock';
import type { Handler, HandlerFnResult } from './shared.types';

describe('mock', () => {
  const result: HandlerFnResult = {
    statusCode: 201,
    response: 'test',
    contentType: 'text/plain',
  };

  const handler: Handler = {
    path: '/test',
    fn: jest.fn().mockResolvedValue(result),
  };

  describe('when request body is a string', () => {
    it('mocks', async () => {
      mock('http://example.com', handler);
      const response = await fetch('http://example.com/test', {
        method: 'POST',
        body: 'test',
      });
      expect(handler.fn).toBeCalled();
      expect(response.status).toBe(result.statusCode);
      await expect(response.text()).resolves.toBe(result.response);
    });
  });

  describe('when request body is JSON', () => {
    it('mocks', async () => {
      mock('http://example.com', handler);
      const response = await fetch('http://example.com/test', {
        method: 'POST',
        body: JSON.stringify({ test: 'test' }),
      });
      expect(handler.fn).toBeCalled();
      expect(response.status).toBe(result.statusCode);
      await expect(response.text()).resolves.toBe(result.response);
    });
  });
});
