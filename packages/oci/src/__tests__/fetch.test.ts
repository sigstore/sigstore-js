/*
Copyright 2024 The Sigstore Authors.

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
import fetch from '../fetch';

describe('fetch', () => {
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

        .reply(200, responseBody);
    });

    it('calls fetch with the correct arguments', async () => {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body,
        retry: false,
      });

      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when there are no fetch options', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL).get(path).reply(200, responseBody);
    });

    it('calls fetch with the correct arguments', async () => {
      const response = await fetch(url);

      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when there is a 500 error with no retry option', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL).post(path).reply(500, { message: 'oops' });
    });

    it('returns the 500 response', async () => {
      const response = await fetch(url, { method: 'POST' });
      expect(response.status).toBe(500);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when there is a 500 error with retry disabled', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL).post(path).reply(500, { message: 'oops' });
    });

    it('returns the 500 response', async () => {
      const response = await fetch(url, { method: 'POST', retry: false });
      expect(response.status).toBe(500);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when there is a 408 error with a successful retry', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL)
        .post(path)
        .reply(408, {})
        .post(path)
        .reply(200, responseBody);
    });

    it('returns the response without error', async () => {
      const response = await fetch(url, {
        method: 'POST',
        retry: { retries: 2, factor: 0 },
      });
      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when there is a non-retryable error', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL).post(path).reply(401, { message: 'unauthorized' });
    });

    it('returns the error response', async () => {
      const response = await fetch(url, { method: 'POST', retry: true });
      expect(response.status).toBe(401);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when the request times-out after retry', () => {
    let scope: nock.Scope;

    beforeEach(() => {
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
        fetch(url, {
          method: 'POST',
          retry: { retries: 1, factor: 0, minTimeout: 0 },
          timeout: 1,
        })
      ).rejects.toThrow(/network timeout/i);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when the first request times-out but succeds on retry', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL)
        .post(path)
        .delay(1000)
        .reply(200, responseBody)
        .post(path)
        .reply(200, responseBody);
    });

    it('returns the response without error', async () => {
      const response = await fetch(url, {
        method: 'POST',
        retry: 2,
        timeout: 500,
      });
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
      const response = await fetch(url, {
        method: 'POST',
        retry: { retries: 4, factor: 0, minTimeout: 0 },
      });
      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });
});

describe('fetch.defaults', () => {
  const baseURL = 'https://example.com';
  const path = '/foo/bar';
  const url = `${baseURL}${path}`;
  const responseBody = { greeting: 'hello' };

  afterEach(() => {
    nock.cleanAll();
  });

  describe('when some fetch params are defaulted', () => {
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
        .reply(200, responseBody);
    });

    it('calls fetch with the correct arguments', async () => {
      const f = fetch.defaults({ headers }).defaults({ method: 'POST' });
      const response = await f(url, { body, retry: false });

      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when all fetch params are defaulted', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL).get(path).reply(200, responseBody);
    });

    it('calls fetch with the correct arguments', async () => {
      const f = fetch.defaults({ method: 'GET' });
      const response = await f(url);

      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });

  describe('when no fetch params are defaulted', () => {
    let scope: nock.Scope;

    beforeEach(() => {
      scope = nock(baseURL).get(path).reply(200, responseBody);
    });

    it('calls fetch with the correct arguments', async () => {
      const response = await fetch.defaults().defaults()(url);

      expect(await response.json()).toEqual(responseBody);
      expect(scope.isDone()).toBe(true);
    });
  });
});
