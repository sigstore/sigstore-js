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
