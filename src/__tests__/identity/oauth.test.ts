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
import { fromPartial } from '@total-typescript/shoehorn';
import child_process, { ChildProcess } from 'child_process';
import fetch from 'make-fetch-happen';
import nock from 'nock';
import { URL } from 'url';

import { Issuer } from '../../identity/issuer';
import { OAuthProvider } from '../../identity/oauth';

jest.mock('child_process', () => ({
  exec: jest.fn(),
}));

describe('OAuthProvider', () => {
  const baseURL = 'http://localhost:8080';
  const issuer = new Issuer(baseURL);
  const subject = new OAuthProvider({ issuer, clientID: 'sigstore' });

  const mockedExec = jest.mocked(child_process.exec);

  beforeEach(() => {
    mockedExec.mockReset();
  });

  describe('#getToken', () => {
    const authEndpoint = '/auth';
    const tokenEndpoint = '/token';

    const openIDConfig = {
      authorization_endpoint: `${baseURL}${authEndpoint}`,
      token_endpoint: `${baseURL}${tokenEndpoint}`,
    };

    const authCode = 'a1b2c3';
    const idToken = 'x.y.z';

    beforeEach(() => {
      mockedExec.mockReset();
      mockedExec.mockImplementationOnce(sendFakeAuthResponse(authCode));

      nock(baseURL)
        .get('/.well-known/openid-configuration')
        .reply(200, openIDConfig);

      nock(baseURL)
        .post(tokenEndpoint, {
          code: authCode,
          grant_type: 'authorization_code',
          redirect_uri: /.*/,
          code_verifier: /.*/,
        })
        .reply(200, { id_token: idToken });
    });

    it('returns the retrieved token', async () => {
      const token = await subject.getToken();

      expect(token).toBe(idToken);
    });

    it('errors on unsupported platforms', async () => {
      const platform = Object.getOwnPropertyDescriptor(process, 'platform');

      Object.defineProperty(process, 'platform', { value: 'fakeos' });

      await expect(subject.getToken()).rejects.toBe(
        'OAuth: unsupported platform: fakeos'
      );

      Object.defineProperty(
        process,
        'platform',
        platform as PropertyDescriptor
      );
    });
  });
});

type ExecFuncArgs = Parameters<typeof child_process.exec>;

function sendFakeAuthResponse(
  code: string
): (...args: ExecFuncArgs) => ChildProcess {
  return (command, _, cb): ChildProcess => {
    // Retrieve the redirect URL and the state value from the URL
    // that would have been used for the authorization request
    let chunk = 1;
    if (process.platform === 'win32') {
      chunk = 2;
    }
    const authRequestURL = new URL(command.split(' ')[chunk].replace(/"/g, ''));
    const redirectURL = authRequestURL.searchParams.get('redirect_uri');
    const state = authRequestURL.searchParams.get('state');

    if (redirectURL && state && cb) {
      // Fake the redirect that would have been sent to the in-process server
      // with the auth code and state values.
      const url = new URL(redirectURL);
      url.searchParams.set('code', code);
      url.searchParams.set('state', state);
      fetch(url.href, { method: 'GET' }).then(() => cb(null, '', ''));
    } else {
      throw new Error('Invalid auth request');
    }

    return fromPartial({});
  };
}
