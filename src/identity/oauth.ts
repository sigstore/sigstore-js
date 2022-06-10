import http from 'http';
import { AddressInfo } from 'net';
import { URLSearchParams, URL } from 'url';
import child_process from 'child_process';
import assert from 'assert';
import crypto from 'crypto';
import fetch from 'make-fetch-happen';

import { Provider } from './provider';
import { hash, randomBytes } from '../crypto';
import { base64Encode } from '../util';
import { Issuer } from './issuer';

export class OAuthProvider implements Provider {
  private clientID: string;
  private clientSecret: string;
  private issuer: Issuer;
  private state: string;
  private codeVerifier?: string;
  private redirectURI?: string;

  constructor(clientID: string, clientSecret: string, issuer: Issuer) {
    this.clientID = clientID;
    this.clientSecret = clientSecret;
    this.issuer = issuer;
    this.state = crypto.randomUUID();
  }

  public async getToken(): Promise<string> {
    this.codeVerifier = await this.generateCodeVerifier();
    const authCode = await this.initiateAuthRequest();
    return this.getIDToken(authCode);
  }

  // Initates the authorization request. This will start an HTTP server to
  // receive the post-auth redirect and then open the user's default browser to
  // the provider's authorization page.
  private async initiateAuthRequest(): Promise<string> {
    const server = http.createServer();

    // Start server and wait till it is listening
    await new Promise<void>((resolve) => {
      server.listen(0, resolve);
    });

    // Get port the server is listening on and construct the server URL
    const port = (server.address() as AddressInfo).port;
    this.redirectURI = `http://localhost:${port}`;

    const result = new Promise<string>((resolve, reject) => {
      // Set-up handler for post-auth redirect
      server.on('request', (req, res) => {
        if (!req.url) {
          reject('invalid server request');
          return;
        }

        res.writeHead(200);
        res.end('Auth Successful');

        // Parse incoming request URL
        const query = new URL(req.url, this.redirectURI).searchParams;

        // Check to see if the state matches
        if (query.get('state') !== this.state) {
          reject('invalid state value');
          return;
        }

        const authCode = query.get('code');
        if (!authCode) {
          reject('authorization code not found');
        } else {
          resolve(authCode);
        }

        server.close();
      });
    });

    // Open browser to start authorization request
    const authBaseURL = await this.issuer.authEndpoint();
    const authURL = this.getAuthRequestURL(authBaseURL);
    await this.openURL(authURL);

    return result;
  }

  // Uses the provided authorization code, to retrieve the ID token from the
  // provider
  private async getIDToken(authCode: string): Promise<string> {
    assert(this.redirectURI);
    assert(this.codeVerifier);

    const tokenEndpointURL = await this.issuer.tokenEndpoint();

    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', authCode);
    params.append('redirect_uri', this.redirectURI);
    params.append('code_verifier', this.codeVerifier);

    const response = await fetch(tokenEndpointURL, {
      method: 'POST',
      headers: { Authorization: `Basic ${this.getBasicAuthHeaderValue()}` },
      body: params,
    }).then((r) => r.json());

    return response.id_token;
  }

  // Construct the basic auth header value from the client ID and secret
  private getBasicAuthHeaderValue(): string {
    return base64Encode(`${this.clientID}:${this.clientSecret}`);
  }

  // Generate starting URL for authorization request
  private getAuthRequestURL(baseURL: string): string {
    const params = this.getAuthRequestParams();
    return `${baseURL}?${params.toString()}`;
  }

  // Collect parameters for authorization request
  private getAuthRequestParams(): URLSearchParams {
    assert(this.redirectURI);
    const codeChallenge = this.getCodeChallenge();

    return new URLSearchParams({
      response_type: 'code',
      client_id: this.clientID,
      client_secret: this.clientSecret,
      scope: 'openid email',
      redirect_uri: this.redirectURI,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state: this.state,
      nonce: crypto.randomUUID(),
    });
  }

  // Generate code challenge for authorization request
  private getCodeChallenge(): string {
    assert(this.codeVerifier);
    return hash(this.codeVerifier, 'base64url');
  }

  // Generate random code verifier value
  private async generateCodeVerifier(): Promise<string> {
    return randomBytes(32).then((b) => b.toString('base64url'));
  }

  // Open the supplied URL in the user's default browser
  // TODO: probably not cross-platform
  private async openURL(url: string) {
    return new Promise<void>((resolve, reject) => {
      child_process.exec(`open "${url}"`, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
}
