import fetch from 'make-fetch-happen';
import { Provider } from './provider';
import { promiseAny } from '../util';

type ProviderFunc = (audience: string) => Promise<string>;

// Collection of all the CI-specific providers we have implemented
const providers: ProviderFunc[] = [getGHAToken];

/**
 * CIContextProvider is a composite identity provider which will iterate
 * over all of the CI-specific providers and return the token from the first
 * one that resolves.
 */
export class CIContextProvider implements Provider {
  private audience: string;

  constructor(audience: string) {
    this.audience = audience;
  }

  // Invoke all registered ProviderFuncs and return the value of whichever one
  // resolves first.
  public async getToken() {
    return promiseAny(
      providers.map((getToken) => getToken(this.audience))
    ).catch(() => Promise.reject('no tokens available'));
  }
}

/**
 * getGHAToken can retrieve an OIDC token when running in a GitHub Actions
 * workflow
 */
async function getGHAToken(audience: string): Promise<string> {
  // Check to see if we're running in GitHub Actions
  if (
    !process.env.ACTIONS_ID_TOKEN_REQUEST_URL ||
    !process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  ) {
    return Promise.reject('no token available');
  }

  // Construct URL to request token w/ appropriate audience
  const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
  url.searchParams.append('audience', audience);

  const response = await fetch(url.href, {
    retry: 2,
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`,
    },
  });

  return response.json().then((data) => data.value);
}
