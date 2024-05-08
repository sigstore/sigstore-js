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
import { fetchWithRetry } from '../../external/fetch';

describe('postWithRetry', () => {
  const baseURL = 'https://example.com';
  const path = '/foo/bar';
  const url = `${baseURL}${path}`;
  const responseBody = { greeting: 'hello' };

  afterEach(() => {
    nock.cleanAll();
  });

  describe('when the request is successful', () => {
    let scope: nock.Scope;
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    const body = JSON.stringify({ foo: 'bar' });

    beforeEach(() => {
      scope = nock(baseURL)
        .post(path, body)
        .matchHeader('content-type', 'application/json')
        .matchHeader('accept', 'application/json')
        .matchHeader('user-agent', /sigstore-js/)

        .reply(200, responseBody);
    });

    it('calls fetch with the correct arguments', async () => {
      const response = await fetchWithRetry(url, {
        headers,
        body,
        retry: false,
      });

      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when there is a 500 error with no retries', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL).post(path).reply(500, { message: 'oops' });
    });

    it('throws an error', async () => {
      await expect(fetchWithRetry(url, {})).rejects.toThrow(/oops/);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when there is a 408 error with a retry', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL)
        .post(path)
        .reply(408, {})
        .post(path)
        .reply(200, responseBody);
    });

    it('returns the response without error', async () => {
      const response = await fetchWithRetry(url, { retry: 2 });
      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when there is a non-retryable error', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL).post(path).reply(401, { message: 'unauthorized' });
    });

    it('throws an error', async () => {
      await expect(fetchWithRetry(url, {})).rejects.toThrow(/unauthorized/);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when the request times-out with an unsuccessful retry', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      // Two requests are mocked to simulate the first request timing out
      scope = nock(baseURL)
        .post(path)
        .delay(1000)
        .reply(200, responseBody)
        .post(path)
        .delay(1000)
        .reply(200, responseBody);
    });

    it('throws an error', async () => {
      await expect(
        fetchWithRetry(url, { retry: true, timeout: 1 })
      ).rejects.toThrow(/network timeout/i);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when the request times-out with a sucessful retry', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      // Two requests are mocked to simulate the first request timing out
      scope = nock(baseURL)
        .post(path)
        .delay(1000)
        .reply(200, responseBody)
        .post(path)
        .reply(200, responseBody);
    });

    it('returns the response without error', async () => {
      const response = await fetchWithRetry(url, { retry: 2, timeout: 500 });
      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when the request succeeds after a lot of retries', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL)
        .post(path)
        .replyWithError({ code: 'ECONNRESET' })
        .post(path)
        .reply(408, {})
        .post(path)
        .reply(501, {})
        .post(path)
        .reply(429, {})
        .post(path)
        .reply(200, responseBody);
    });

    it('returns the response without error', async () => {
      const response = await fetchWithRetry(url, {
        retry: { retries: 4, factor: 0, minTimeout: 1, maxTimeout: 1 },
      });
      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });
});
