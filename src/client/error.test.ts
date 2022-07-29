/*
Copyright 2022 GitHub, Inc

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
