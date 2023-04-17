/*
Copyright 2023 The Sigstore Authors.

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
import { CA, CAClient } from './ca';
import identity, { Provider } from './identity';
import { TLog, TLogClient } from './tlog';
import * as sigstore from './types/sigstore';

import type { KeySelector } from './verify';

interface CAOptions {
  fulcioURL?: string;
}

interface TLogOptions {
  rekorURL?: string;
}

export interface IdentityProviderOptions {
  identityToken?: string;
  oidcIssuer?: string;
  oidcClientID?: string;
  oidcClientSecret?: string;
  oidcRedirectURL?: string;
}

export interface TUFOptions {
  tufMirrorURL?: string;
  tufRootPath?: string;
}

export type SignOptions = CAOptions & TLogOptions & IdentityProviderOptions;

export type VerifyOptions = {
  ctLogThreshold?: number;
  tlogThreshold?: number;
  certificateIssuer?: string;
  certificateIdentityEmail?: string;
  certificateIdentityURI?: string;
  certificateOIDs?: Record<string, string>;
  keySelector?: KeySelector;
} & TLogOptions &
  TUFOptions;

export const DEFAULT_FULCIO_URL = 'https://fulcio.sigstore.dev';
export const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';

export function createCAClient(options: { fulcioURL?: string }): CA {
  return new CAClient({
    fulcioBaseURL: options.fulcioURL || DEFAULT_FULCIO_URL,
  });
}

export function createTLogClient(options: { rekorURL?: string }): TLog {
  return new TLogClient({
    rekorBaseURL: options.rekorURL || DEFAULT_REKOR_URL,
  });
}

// Assembles the AtifactVerificationOptions from the supplied VerifyOptions.
export function artifactVerificationOptions(
  options: VerifyOptions
): sigstore.RequiredArtifactVerificationOptions {
  // The trusted signers are only used if the options contain a certificate
  // issuer
  let signers: sigstore.RequiredArtifactVerificationOptions['signers'];
  if (options.certificateIssuer) {
    let san: sigstore.SubjectAlternativeName | undefined = undefined;
    if (options.certificateIdentityEmail) {
      san = {
        type: sigstore.SubjectAlternativeNameType.EMAIL,
        identity: {
          $case: 'value',
          value: options.certificateIdentityEmail,
        },
      };
    } else if (options.certificateIdentityURI) {
      san = {
        type: sigstore.SubjectAlternativeNameType.URI,
        identity: {
          $case: 'value',
          value: options.certificateIdentityURI,
        },
      };
    }

    const oids = Object.entries(
      options.certificateOIDs || {}
    ).map<sigstore.ObjectIdentifierValuePair>(([oid, value]) => ({
      oid: { id: oid.split('.').map((s) => parseInt(s, 10)) },
      value: Buffer.from(value),
    }));

    signers = {
      $case: 'certificateIdentities',
      certificateIdentities: {
        identities: [
          {
            issuer: options.certificateIssuer,
            san: san,
            oids: oids,
          },
        ],
      },
    };
  }

  // Construct the artifact verification options w/ defaults
  return {
    ctlogOptions: {
      disable: false,
      threshold: options.ctLogThreshold || 1,
      detachedSct: false,
    },
    tlogOptions: {
      disable: false,
      threshold: options.tlogThreshold || 1,
      performOnlineVerification: false,
    },
    signers,
  };
}

// Translates the IdenityProviderOptions into a list of Providers which
// should be queried to retrieve an identity token.
export function identityProviders(
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
        identity.oauthProvider({
          issuer: options.oidcIssuer,
          clientID: options.oidcClientID,
          clientSecret: options.oidcClientSecret,
          redirectURL: options.oidcRedirectURL,
        })
      );
    }
  }

  return idps;
}
