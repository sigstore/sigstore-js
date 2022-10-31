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
import {
  bundleFromJSON,
  bundleToJSON,
  envelopeFromJSON,
  envelopeToJSON,
  Envelope as DSSEEnvelope,
  SerializedEnvelope,
  SerializedBundle,
} from './types/bundle';
import { extractSignatureMaterial, SignerFunc } from './types/signature';
import { Verifier } from './verify';
import { dsse } from './util';

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

export type VerifierOptions = TLogOptions;

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
): Promise<boolean> {
  const tlog = createTLogClient(options);
  const verifier = new Verifier({ tlog });

  const b = bundleFromJSON(bundle);
  return verifier.verify(b, data);
}

export async function createDSSEEnvelope(
  payload: Buffer,
  payloadType: string,
  options: {
    signer: SignerFunc;
  }
): Promise<Envelope> {
  // Pre-authentication encoding to be signed
  const paeBuffer = dsse.preAuthEncoding(payloadType, payload);

  // Get signature and verification material for pae
  const sigMaterial = await options.signer(paeBuffer);

  const envelope: DSSEEnvelope = {
    payloadType,
    payload,
    signatures: [
      {
        keyid: sigMaterial.key?.id || '',
        sig: sigMaterial.signature,
      },
    ],
  };

  return envelopeToJSON(envelope) as Envelope;
}

// Accepts a signed DSSE envelope and a PEM-encoded public key to be added to the
// transparency log. Returns a Sigstore bundle suitable for offline verification.
export async function createRekorEntry(
  dsseEnvelope: Envelope,
  publicKey: string,
  options: SignOptions = {}
): Promise<Bundle> {
  const envelope = envelopeFromJSON(dsseEnvelope);
  const tlog = createTLogClient(options);

  const sigMaterial = extractSignatureMaterial(envelope, publicKey);
  const bundle = await tlog.createDSSEEntry(envelope, sigMaterial);
  return bundleToJSON(bundle) as Bundle;
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
