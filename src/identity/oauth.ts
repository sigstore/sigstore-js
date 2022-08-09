/*
Copyright 2022 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import http from 'http';
import { AddressInfo, Socket } from 'net';
import { URLSearchParams, URL } from 'url';
import child_process from 'child_process';
import assert from 'assert';
import fetch from 'make-fetch-happen';

import { Provider } from './provider';
import { hash, randomBytes } from '../crypto';
import { base64Encode } from '../util';
import { Issuer } from './issuer';

export class OAuthProvider implements Provider {
  private clientID: string;
  private clientSecret: string;
  private issuer: Issuer;
  private codeVerifier: string;
  private state: string;
  private redirectURI?: string;

  constructor(issuer: Issuer, clientID: string, clientSecret?: string) {
    this.clientID = clientID;
    this.clientSecret = clientSecret || '';
    this.issuer = issuer;
    this.codeVerifier = generateRandomString(32);
    this.state = generateRandomString(16);
  }

  public async getToken(): Promise<string> {
    const authCode = await this.initiateAuthRequest();
    return this.getIDToken(authCode);
  }

  // Initates the authorization request. This will start an HTTP server to
  // receive the post-auth redirect and then open the user's default browser to
  // the provider's authorization page.
  private async initiateAuthRequest(): Promise<string> {
    const server = http.createServer();
    const sockets = new Set<Socket>();

    // Start server and wait till it is listening
    await new Promise<void>((resolve) => {
      server.listen(0, resolve);
    });

    // Keep track of connections to the server so we can force a shutdown
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.once('close', () => {
        sockets.delete(socket);
      });
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

        // Force-close any open connections to the server so we can get a
        // clean shutdown
        for (const socket of sockets) {
          socket.destroy();
          sockets.delete(socket);
        }

        // Return auth code once we've shutdown server
        server.close(() => {
          if (!authCode) {
            reject('authorization code not found');
          } else {
            resolve(authCode);
          }
        });
      });
    });

    try {
      // Open browser to start authorization request
      const authBaseURL = await this.issuer.authEndpoint();
      const authURL = this.getAuthRequestURL(authBaseURL);
      await this.openURL(authURL);
    } catch (err) {
      // Prevent leaked server handler on error
      server.close();
      throw err;
    }

    return result;
  }

  // Uses the provided authorization code, to retrieve the ID token from the
  // provider
  private async getIDToken(authCode: string): Promise<string> {
    assert(this.redirectURI);

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
      nonce: generateRandomString(16),
    });
  }

  // Generate code challenge for authorization request
  private getCodeChallenge(): string {
    return base64URLEncode(hash(this.codeVerifier, 'base64'));
  }

  // Open the supplied URL in the user's default browser
  private async openURL(url: string) {
    return new Promise<void>((resolve, reject) => {
      let open = null;
      let command = `"${url}"`;
      switch (process.platform) {
        case 'darwin':
          open = 'open';
          break;
        case 'linux' || 'freebsd' || 'netbsd' || 'openbsd':
          open = 'xdg-open';
          break;
        case 'win32':
          open = 'start';
          command = `"" ${command}`;
          break;
        default:
          return reject(`OAuth: unsupported platform: ${process.platform}`);
      }
      console.error(`Your browser will now be opened to: ${url}`);
      child_process.exec(`${open} ${command}`, undefined, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
}

// Generate random code verifier value
function generateRandomString(len: number): string {
  return base64URLEncode(randomBytes(len).toString('base64'));
}

// Older versions of node don't support 'base64url' encoding in Buffer's
// toString() so we have to provide our own
function base64URLEncode(str: string): string {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
