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
import { Fulcio } from './client';
import identity, { Provider } from './identity';
import { Signer } from './sign';
import { TLog, TLogClient } from './tlog';
import { getKeys } from './tlog/keys';
import {
  bundleFromJSON,
  bundleToJSON,
  SerializedBundle,
  SerializedEnvelope,
} from './types/bundle';
import { GetPublicKeyFunc, Verifier } from './verify';

export * as utils from './sigstore-utils';

export const DEFAULT_REKOR_BASE_URL = 'https://rekor.sigstore.dev';

interface TLogOptions {
  rekorBaseURL?: string;
}

export type SignOptions = {
  fulcioBaseURL?: string;
  rekorBaseURL?: string;
  identityToken?: string;
  oidcIssuer?: string;
  oidcClientID?: string;
  oidcClientSecret?: string;
} & TLogOptions;

export type VerifierOptions = {
  getPublicKey?: GetPublicKeyFunc;
} & TLogOptions;

export type Bundle = SerializedBundle;

export type Envelope = SerializedEnvelope;

type IdentityProviderOptions = Pick<
  SignOptions,
  'identityToken' | 'oidcIssuer' | 'oidcClientID' | 'oidcClientSecret'
>;

function createTLogClient(options: { rekorBaseURL?: string }): TLog {
  return new TLogClient({
    rekorBaseURL: options.rekorBaseURL || DEFAULT_REKOR_BASE_URL,
  });
}

export async function sign(
  payload: Buffer,
  options: SignOptions = {}
): Promise<Bundle> {
  const fulcio = new Fulcio({ baseURL: options.fulcioBaseURL });
  const tlog = createTLogClient(options);
  const idps = configureIdentityProviders(options);
  const signer = new Signer({
    fulcio,
    tlog,
    identityProviders: idps,
  });

  const bundle = await signer.signBlob(payload);
  return bundleToJSON(bundle) as Bundle;
}

export async function signAttestation(
  payload: Buffer,
  payloadType: string,
  options: SignOptions = {}
): Promise<Bundle> {
  const fulcio = new Fulcio({ baseURL: options.fulcioBaseURL });
  const tlog = createTLogClient(options);
  const idps = configureIdentityProviders(options);
  const signer = new Signer({
    fulcio,
    tlog,
    identityProviders: idps,
  });

  const bundle = await signer.signAttestation(payload, payloadType);
  return bundleToJSON(bundle) as Bundle;
}

export async function verify(
  bundle: Bundle,
  data?: Buffer,
  options: VerifierOptions = {}
): Promise<void> {
  const tlog = createTLogClient(options);
  const tlogKeys = getKeys();
  const verifier = new Verifier({
    tlog,
    tlogKeys,
    getPublicKey: options.getPublicKey,
  });

  const b = bundleFromJSON(bundle);
  return verifier.verifyOffline(b, data);
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
