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
import { CIContextProvider } from './ci';
import { Issuer } from './issuer';
import { OAuthProvider } from './oauth';
import type { Provider } from './provider';

export const staticIdentityProvider = (token: string): Provider => {
  return {
    getToken: async () => token,
  };
};

export const ciContextIdentityProvider = (): Provider => {
  return new CIContextProvider('sigstore');
};

export const oauthIdentityProvider = (options: {
  issuer: string;
  clientID: string;
  clientSecret?: string;
  redirectURL?: string;
}): Provider => {
  return new OAuthProvider({
    issuer: new Issuer(options.issuer),
    clientID: options.clientID,
    clientSecret: options.clientSecret,
    redirectURL: options.redirectURL,
  });
};

export { Provider } from './provider';
