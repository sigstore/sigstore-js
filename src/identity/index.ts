import { default as ciContextProvider } from './ci';
import { Issuer } from './issuer';
import { OAuthProvider } from './oauth';
import { Provider } from './provider';

/**
 * oauthProvider returns a new OAuthProvider instance with the given config.
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

export default {
  ciContextProvider,
  oauthProvider,
};

export { Provider } from './provider';
