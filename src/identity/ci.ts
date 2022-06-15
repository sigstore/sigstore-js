import { Provider } from './provider';
import fetch from 'make-fetch-happen';

type ProviderFunc = () => Promise<string | undefined>;

// Collection of all the CI-specific providers we have implemented
const providers: ProviderFunc[] = [getGHAToken];

/**
 * CIContextProvider is a composite identity provider which will iterate
 * over all of the CI-specific providers and return the token from the first
 * one that returns a non-undefined value.
 */
class CIContextProvider implements Provider {
  public async getToken() {
    for (const provider of providers) {
      const token = await provider();

      if (token) {
        return token;
      }
    }
  }
}

/**
 * getGHAToken can retrieve an OIDC token when running in a GitHub Actions
 * workflow
 */
async function getGHAToken(): Promise<string | undefined> {
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
    retry: 2,
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`,
    },
  });

  return response.json().then((data) => data.value);
}

export default new CIContextProvider();
