import open from 'open';
import { initializeOAuthClient } from './client';
import { CallbackServer } from './server';

import type { IdentityProvider } from 'sigstore';

export interface OAuthIdentityProviderOptions {
  issuer: string;
  clientID: string;
  clientSecret?: string;
  redirectURL?: string;
}

export class OAuthIdentityProvider implements IdentityProvider {
  private server: CallbackServer;
  private issuer: string;
  private clientID: string;
  private clientSecret?: string;

  constructor(options: OAuthIdentityProviderOptions) {
    this.issuer = options.issuer;
    this.clientID = options.clientID;
    this.clientSecret = options.clientSecret;

    let serverOpts;
    if (options.redirectURL) {
      const url = new URL(options.redirectURL);
      serverOpts = { hostname: url.hostname, port: Number(url.port) };
    } else {
      serverOpts = { hostname: 'localhost', port: 0 };
    }

    this.server = new CallbackServer(serverOpts);
  }

  public async getToken(): Promise<string> {
    // Start server to receive OAuth callback
    const serverURL = await this.server.start();

    // Initialize OAuth client
    const client = await initializeOAuthClient({
      issuer: this.issuer,
      redirectURL: serverURL,
      clientID: this.clientID,
      clientSecret: this.clientSecret,
    });

    // Open browser to OAuth login page
    open(client.authorizationUrl);

    /* istanbul ignore next */
    if (!this.server.callback) {
      throw new Error('callback server not started');
    }

    // Wait for callback and exchange auth code for ID token
    return this.server.callback.then((authCode) => client.getIDToken(authCode));
  }
}
