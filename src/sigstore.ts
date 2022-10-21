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
import { Fulcio, Rekor } from './client';
import identity, { Provider } from './identity';
import { Signer } from './sign';
import { Bundle as BundleSerializer, SerializedBundle } from './types/bundle';
import { Verifier } from './verify';

export interface SignOptions {
  fulcioBaseURL?: string;
  rekorBaseURL?: string;
  identityToken?: string;
  oidcIssuer?: string;
  oidcClientID?: string;
  oidcClientSecret?: string;
}

export interface VerifierOptions {
  rekorBaseURL?: string;
}

export function getRekorBaseUrl(options?: SignOptions) {
  return Rekor.getBaseUrl(options?.rekorBaseURL);
}

export type Bundle = SerializedBundle;

type IdentityProviderOptions = Pick<
  SignOptions,
  'identityToken' | 'oidcIssuer' | 'oidcClientID' | 'oidcClientSecret'
>;

export async function sign(
  payload: Buffer,
  options: SignOptions = {}
): Promise<Bundle> {
  const fulcio = new Fulcio({ baseURL: options.fulcioBaseURL });
  const rekor = new Rekor({ baseURL: options.rekorBaseURL });
  const idps = configureIdentityProviders(options);
  const signer = new Signer({
    fulcio,
    rekor,
    identityProviders: idps,
  });

  const bundle = await signer.signBlob(payload);
  return BundleSerializer.toJSON(bundle) as Bundle;
}

export async function signAttestation(
  payload: Buffer,
  payloadType: string,
  options: SignOptions = {}
): Promise<Bundle> {
  const fulcio = new Fulcio({ baseURL: options.fulcioBaseURL });
  const rekor = new Rekor({ baseURL: options.rekorBaseURL });
  const idps = configureIdentityProviders(options);
  const signer = new Signer({
    fulcio,
    rekor,
    identityProviders: idps,
  });

  const bundle = await signer.signAttestation(payload, payloadType);
  return BundleSerializer.toJSON(bundle) as Bundle;
}

export async function verify(
  bundle: Bundle,
  data?: Buffer,
  options: VerifierOptions = {}
): Promise<boolean> {
  const rekor = new Rekor({ baseURL: options.rekorBaseURL });
  const verifier = new Verifier({ rekor });

  const b = BundleSerializer.fromJSON(bundle);
  return verifier.verify(b, data);
}

// Translates the IdenityProviderOptions into a list of Providers which
// should be queried to retrieve an identity token.
function configureIdentityProviders(
  options: IdentityProviderOptions
): Provider[] {
  const idps: Provider[] = [];
  const token = options.identityToken;

  // If an explicit identity token is provided, use that. Setup a dummy
  // provider that just returns the token. Otherwise, setup the CI context
  // provider and (optionally) the OAuth provider.
  if (token) {
    idps.push({ getToken: () => Promise.resolve(token) });
  } else {
    idps.push(identity.ciContextProvider());
    if (options.oidcIssuer && options.oidcClientID) {
      idps.push(
        identity.oauthProvider(
          options.oidcIssuer,
          options.oidcClientID,
          options.oidcClientSecret
        )
      );
    }
  }

  return idps;
}
