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
import { ciContextIdentityProvider } from './identity';
import { createNotary } from './notary';
import * as sigstore from './types/sigstore';

import type { Provider } from './identity';
import type { BundleType, Notary, NotaryFactoryOptions } from './notary';
import type { SignerFunc } from './signatory';
import type { FetchOptions, Retry } from './types/fetch';
import type { KeySelector } from './verify';

interface CAOptions {
  identityProvider?: Provider;
  fulcioURL?: string;
}

interface TLogOptions {
  rekorURL?: string;
}

interface TSAOptions {
  tsaServerURL?: string;
}

// TODO: Remove this interface once we have a better way to pass identity
interface IdentityOptions {
  identityToken?: string;
  oidcIssuer?: string;
  oidcClientID?: string;
  oidcClientSecret?: string;
  oidcRedirectURL?: string;
}

export type TUFOptions = {
  tufMirrorURL?: string;
  tufRootPath?: string;
  tufCachePath?: string;
} & FetchOptions;

export type SignOptions = {
  identityProvider?: Provider;
  tlogUpload?: boolean;
  signer?: SignerFunc;
} & CAOptions &
  TLogOptions &
  TSAOptions &
  FetchOptions &
  IdentityOptions;

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

export const DEFAULT_RETRY: Retry = { retries: 2 };
export const DEFAULT_TIMEOUT = 5000;

export function notary(
  options: SignOptions & { bundleType: BundleType }
): Notary {
  return createNotary({
    bundleType: options.bundleType,
    ...notaryOptions(options),
  });
}

// Assembles the NotaryFactoryOptions from the supplied SignOptions, providing
// defaults where necessary.
function notaryOptions(
  options: SignOptions
): Omit<NotaryFactoryOptions, 'bundleType'> {
  const tlogUpload = options.tlogUpload ?? true;

  const fulcioBaseURL = options.fulcioURL || DEFAULT_FULCIO_URL;

  // An explicit identity provider takes, precedence, but if we're running in a
  // CI context, we'll fallback to use the CI context provider.
  const identityProvider =
    options.identityProvider ||
    ('CI' in process.env && ciContextIdentityProvider()) ||
    undefined;

  const rekorBaseURL = tlogUpload
    ? options.rekorURL || DEFAULT_REKOR_URL
    : undefined;
  const tsaBaseURL = options.tsaServerURL;
  const retry = options.retry ?? DEFAULT_RETRY;
  const timeout = options.timeout ?? DEFAULT_TIMEOUT;

  const signer = options.signer;

  return {
    fulcioBaseURL,
    identityProvider,
    signer,
    rekorBaseURL,
    tsaBaseURL,
    retry,
    timeout,
  };
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
