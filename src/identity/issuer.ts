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
import fetch, { FetchInterface } from 'make-fetch-happen';

// Standard endpoint for retrieving OpenID configuration information
const OPENID_CONFIG_PATH = '/.well-known/openid-configuration';

interface OpenIDConfig {
  authorization_endpoint: string;
  token_endpoint: string;
}

/**
 * The Issuer reperesents a single OAuth2 provider.
 *
 * The Issuer is configured with a provider's base OAuth2 endpoint which is
 * used to retrieve the associated configuration information.
 */
export class Issuer {
  private baseURL: string;
  private fetch: FetchInterface;

  private config?: OpenIDConfig;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
    this.fetch = fetch.defaults({ retry: 2 });
  }

  public async authEndpoint(): Promise<string> {
    if (!this.config) {
      this.config = await this.loadOpenIDConfig();
    }

    return this.config.authorization_endpoint;
  }

  public async tokenEndpoint(): Promise<string> {
    if (!this.config) {
      this.config = await this.loadOpenIDConfig();
    }

    return this.config.token_endpoint;
  }

  private async loadOpenIDConfig(): Promise<OpenIDConfig> {
    const url = `${this.baseURL}${OPENID_CONFIG_PATH}`;
    return this.fetch(url).then((res) => res.json());
  }
}
