import { Provider } from './provider';
import fetch, { FetchInterface } from 'make-fetch-happen';

/**
 * GHAProvider can retrieve an OIDC token when running in a GitHub Actions
 * workflow
 */
export class GHAProvider implements Provider {
  private fetch: FetchInterface;

  constructor() {
    this.fetch = fetch.defaults({
      retry: 2,
      headers: { Accept: 'application/json' },
    });
  }

  async getToken(): Promise<string | undefined> {
    // Check to see if we're running in GitHub Actions
    if (
      !process.env.ACTIONS_ID_TOKEN_REQUEST_URL ||
      !process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
    ) {
      return;
    }

    // Construct URL to request token w/ appropriate audience
    const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
    url.searchParams.append('audience', 'sigstore');

    const response = await fetch(url.href, {
      headers: {
        Authorization: `Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`,
      },
    });

    return response.json().then((data) => data.value);
  }
}
