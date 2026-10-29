import {
  ClientSecretBasic,
  Configuration,
  None,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  discovery,
  enableNonRepudiationChecks,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
} from 'openid-client';

interface OAuthClientOptions {
  issuer: string;
  redirectURL: string;
  clientID: string;
  clientSecret?: string;
}

// Discover the issuer's configuration and initialize an authorization flow.
export async function initializeOAuthClient(
  options: OAuthClientOptions
): Promise<OAuthClient> {
  const client = await discovery(
    new URL(options.issuer),
    options.clientID,
    options.clientSecret,
    options.clientSecret ? ClientSecretBasic(options.clientSecret) : None(),
    // v6 requires opting in to ID-token signature verification.
    { execute: [enableNonRepudiationChecks] }
  );
  const verifier = randomPKCECodeVerifier();
  const challenge = await calculatePKCECodeChallenge(verifier);

  return new OAuthClient(client, options.redirectURL, verifier, challenge);
}

// Maintain state for a single authorization flow.
class OAuthClient {
  private client: Configuration;
  private redirectURL: string;
  private verifier: string;
  private challenge: string;
  private nonce: string;
  private state: string;

  constructor(
    client: Configuration,
    redirectURL: string,
    verifier: string,
    challenge: string
  ) {
    this.client = client;
    this.redirectURL = new URL(redirectURL).href;
    this.verifier = verifier;
    this.challenge = challenge;
    this.nonce = randomNonce();
    this.state = randomState();
  }

  get authorizationUrl(): string {
    return buildAuthorizationUrl(this.client, {
      scope: 'openid email',
      redirect_uri: this.redirectURL,
      code_challenge: this.challenge,
      code_challenge_method: 'S256',
      state: this.state,
      nonce: this.nonce,
    }).href;
  }

  public async getIDToken(callbackURL: string): Promise<string> {
    const tokenSet = await authorizationCodeGrant(
      this.client,
      new URL(callbackURL, this.redirectURL),
      {
        pkceCodeVerifier: this.verifier,
        expectedState: this.state,
        expectedNonce: this.nonce,
        idTokenExpected: true,
      }
    );
    return tokenSet.id_token!;
  }
}
