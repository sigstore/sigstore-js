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
import {
  BundleBuilder,
  BundleBuilderOptions,
  CIContextProvider,
  DSSEBundleBuilder,
  FulcioSigner,
  IdentityProvider,
  MessageSignatureBundleBuilder,
  RekorWitness,
  Signer,
  TSAWitness,
  Witness,
} from '@sigstore/sign';
import * as sigstore from './types/sigstore';

import type { FetchOptions, Retry } from './types/fetch';
import type { KeySelector } from './verify';

export type SignOptions = {
  fulcioURL?: string;
  identityProvider?: IdentityProvider;
  identityToken?: string;
  rekorURL?: string;
  tlogUpload?: boolean;
  tsaServerURL?: string;
} & FetchOptions;

export type VerifyOptions = {
  ctLogThreshold?: number;
  tlogThreshold?: number;
  certificateIssuer?: string;
  certificateIdentityEmail?: string;
  certificateIdentityURI?: string;
  certificateOIDs?: Record<string, string>;
  keySelector?: KeySelector;
  tufMirrorURL?: string;
  tufRootPath?: string;
  tufCachePath?: string;
} & FetchOptions;

export const DEFAULT_RETRY: Retry = { retries: 2 };
export const DEFAULT_TIMEOUT = 5000;

export type BundleType = 'messageSignature' | 'dsseEnvelope';

export function createBundleBuilder(
  bundleType: 'messageSignature',
  options: SignOptions
): MessageSignatureBundleBuilder;
export function createBundleBuilder(
  bundleType: 'dsseEnvelope',
  options: SignOptions
): DSSEBundleBuilder;
export function createBundleBuilder(
  bundleType: BundleType,
  options: SignOptions
): BundleBuilder {
  const bundlerOptions: BundleBuilderOptions = {
    signer: initSigner(options),
    witnesses: initWitnesses(options),
  };

  switch (bundleType) {
    case 'messageSignature':
      return new MessageSignatureBundleBuilder(bundlerOptions);
    case 'dsseEnvelope':
      return new DSSEBundleBuilder(bundlerOptions);
  }
}

// Instantiate the FulcioSigner based on the supplied options.
function initSigner(options: SignOptions): Signer {
  return new FulcioSigner({
    fulcioBaseURL: options.fulcioURL,
    identityProvider: options.identityProvider || initIdentityProvider(options),
    retry: options.retry ?? DEFAULT_RETRY,
    timeout: options.timeout ?? DEFAULT_TIMEOUT,
  });
}

// Instantiate an identity provider based on the supplied options. If an
// explicit identity token is provided, use that. Otherwise, use the CI
// context provider.
function initIdentityProvider(options: SignOptions): IdentityProvider {
  const token = options.identityToken;

  if (token) {
    return { getToken: () => Promise.resolve(token) };
  } else {
    return new CIContextProvider('sigstore');
  }
}

// Instantiate a collection of witnesses based on the supplied options.
function initWitnesses(options: SignOptions): Witness[] {
  const witnesses: Witness[] = [];

  if (isRekorEnabled(options)) {
    witnesses.push(
      new RekorWitness({
        rekorBaseURL: options.rekorURL,
        fetchOnConflict: false,
        retry: options.retry ?? DEFAULT_RETRY,
        timeout: options.timeout ?? DEFAULT_TIMEOUT,
      })
    );
  }

  if (isTSAEnabled(options)) {
    witnesses.push(
      new TSAWitness({
        tsaBaseURL: options.tsaServerURL,
        retry: options.retry ?? DEFAULT_RETRY,
        timeout: options.timeout ?? DEFAULT_TIMEOUT,
      })
    );
  }

  return witnesses;
}

// Type assertion to ensure that Rekor is enabled
function isRekorEnabled(
  options: SignOptions
): options is SignOptions & { tlogUpload: boolean } {
  return options.tlogUpload !== false;
}

// Type assertion to ensure that TSA is enabled
function isTSAEnabled(
  options: SignOptions
): options is SignOptions & { tsaServerURL: string } {
  return options.tsaServerURL !== undefined;
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
      options.certificateOIDs || /* istanbul ignore next */ {}
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
      disable: options.ctLogThreshold === 0,
      threshold: options.ctLogThreshold ?? 1,
      detachedSct: false,
    },
    tlogOptions: {
      disable: options.tlogThreshold === 0,
      threshold: options.tlogThreshold ?? 1,
      performOnlineVerification: false,
    },
    signers,
  };
}
