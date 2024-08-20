import { BaseClient, Issuer, generators } from 'openid-client';

interface OAuthClientOptions {
  issuer: string;
  redirectURL: string;
  clientID: string;
  clientSecret?: string;
}

// Returns an openid Client instance configured by looking up
// the issuer's configuration from the well-known endpoint.
export async function initializeOAuthClient(
  options: OAuthClientOptions
): Promise<OAuthClient> {
  const authMethod = options.clientSecret ? 'client_secret_basic' : 'none';
  const client = await Issuer.discover(options.issuer).then(
    (issuer) =>
      new issuer.Client({
        client_id: options.clientID,
        client_secret: options.clientSecret,
        token_endpoint_auth_method: authMethod,
      })
  );

  return new OAuthClient(client, options.redirectURL);
}

// Wrapper around an openid-client Client instance to maintain
// state for the authorization flow.
class OAuthClient {
  private client: BaseClient;
  private redirectURL: string;
  private verifier: string;
  private nonce: string;
  private state: string;

  constructor(client: BaseClient, redirectURL: string) {
    this.client = client;
    this.redirectURL = redirectURL;
    this.verifier = generators.codeVerifier(32);
    this.nonce = generators.nonce(32);
    this.state = generators.state(16);
  }

  get authorizationUrl(): string {
    return this.client.authorizationUrl({
      scope: 'openid email',
      redirect_uri: this.redirectURL,
      code_challenge: generators.codeChallenge(this.verifier),
      code_challenge_method: 'S256',
      state: this.state,
      nonce: this.nonce,
    });
  }

  public async getIDToken(callbackURL: string): Promise<string> {
    const params = this.client.callbackParams(callbackURL);
    return (
      this.client
        .callback(this.redirectURL, params, {
          response_type: 'code',
          code_verifier: this.verifier,
          state: this.state,
          nonce: this.nonce,
        })
        .then((tokenSet) => tokenSet.id_token!)
    );
  }
}
