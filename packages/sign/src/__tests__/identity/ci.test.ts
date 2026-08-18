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
import { execFile } from 'node:child_process';
import { CIContextProvider } from '../../identity/ci';

jest.mock('node:child_process');

const mockedExecFile = jest.mocked(execFile);

describe('CIContextProvider', () => {
  const subject = new CIContextProvider('sigstore');

  it('creates an instance', () => {
    expect(subject).toBeTruthy();
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
        const token = await subject.getToken();
        expect(token).toBe(oidcToken);
      });
    });

    describe('when the GHA environment variables are NOT set', () => {
      it('returns undefined', async () => {
        const token = subject.getToken();
        await expect(token).rejects.toBe('CI: no tokens available');
      });
    });

    describe('when running in Buildkite', () => {
      beforeEach(() => {
        process.env.BUILDKITE = 'true';
      });

      afterEach(() => {
        delete process.env.BUILDKITE;
        mockedExecFile.mockReset();
      });

      it('requests and returns an audience-scoped token from the agent', async () => {
        mockedExecFile.mockImplementation((_file, _args, callback) => {
          callback?.(null, 'x.y.z\n', '');
          return undefined as never;
        });

        await expect(subject.getToken()).resolves.toBe('x.y.z');
        expect(mockedExecFile).toHaveBeenCalledWith(
          'buildkite-agent',
          ['oidc', 'request-token', '--audience', 'sigstore'],
          expect.any(Function)
        );
      });

      it('reports no token when the agent request fails', async () => {
        mockedExecFile.mockImplementation((_file, _args, callback) => {
          callback?.(new Error('request failed'), '', '');
          return undefined as never;
        });

        await expect(subject.getToken()).rejects.toBe(
          'CI: no tokens available'
        );
      });

      it('reports no token when the agent returns an empty response', async () => {
        mockedExecFile.mockImplementation((_file, _args, callback) => {
          callback?.(null, '\n', '');
          return undefined as never;
        });

        await expect(subject.getToken()).rejects.toBe(
          'CI: no tokens available'
        );
      });
    });
  });

  describe('#getEnv', () => {
    describe('when the sigstore environment variables are set', () => {
      const token = 'hunter2';

      beforeEach(() => {
        process.env.SIGSTORE_ID_TOKEN = token;
      });

      afterEach(() => {
        delete process.env.SIGSTORE_ID_TOKEN;
      });

      it('returns the token', async () => {
        const token = await subject.getToken();
        expect(token).toBe(token);
      });
    });

    describe('when the sigstore environment variables are NOT set', () => {
      it('returns undefined', async () => {
        const token = subject.getToken();
        await expect(token).rejects.toBe('CI: no tokens available');
      });
    });
  });
});
