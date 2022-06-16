import { CIContextProvider } from './ci';
import { Issuer } from './issuer';
import { OAuthProvider } from './oauth';
import { Provider } from './provider';

/**
 * oauthProvider returns a new Provider instance which attempts to retrieve
 * an identity token from the configured OAuth2 issuer.
 *
 * @param issuer Base URL of the issuer
 * @param clientID Client ID for the issuer
 * @param clientSecret Client secret for the issuer (optional)
 * @returns {Provider}
 */
function oauthProvider(
  issuer: string,
  clientID: string,
  clientSecret?: string
): Provider {
  return new OAuthProvider(new Issuer(issuer), clientID, clientSecret);
}

/**
 * ciContextProvider returns a new Provider instance which attempts to retrieve
 * an identity token from the CI context.
 *
 * @param audience audience claim for the generated token
 * @returns {Provider}
 */
function ciContextProvider(audience = 'sigstore'): Provider {
  return new CIContextProvider(audience);
}

export default {
  ciContextProvider,
  oauthProvider,
};

export { Provider } from './provider';
