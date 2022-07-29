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
import nock from 'nock';
import { Issuer } from './issuer';

describe('Issuer', () => {
  const baseURL = 'http://localhost:8080';
  const subject = new Issuer(baseURL);

  const openIDConfig = {
    authorization_endpoint: 'auth',
    token_endpoint: 'token',
  };

  beforeEach(() => {
    nock.cleanAll();
    nock(baseURL)
      .get('/.well-known/openid-configuration')
      .once()
      .reply(200, openIDConfig);
  });

  it('should create an instance', () => {
    expect(subject).toBeTruthy();
  });

  describe('#authEndpoint', () => {
    it('returns the auth endpoint', async () => {
      const endpoint = await subject.authEndpoint();
      expect(endpoint).toBe(openIDConfig.authorization_endpoint);
    });

    it('only fetches the endpoint once', async () => {
      await subject.authEndpoint();
      const endpoint = await subject.authEndpoint();
      expect(endpoint).toBe(openIDConfig.authorization_endpoint);
    });
  });

  describe('#tokenEndpoint', () => {
    it('returns the token endpoint', async () => {
      const endpoint = await subject.tokenEndpoint();
      expect(endpoint).toBe(openIDConfig.token_endpoint);
    });

    it('only fetches the endpoint once', async () => {
      await subject.tokenEndpoint();
      const endpoint = await subject.tokenEndpoint();
      expect(endpoint).toBe(openIDConfig.token_endpoint);
    });
  });
});
