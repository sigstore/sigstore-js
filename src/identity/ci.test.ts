/*
Copyright 2022 The Sigstore Authors.

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
import { CIContextProvider } from './ci';

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
  });
});
