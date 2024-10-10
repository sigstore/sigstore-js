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
import { crypto } from '@sigstore/core';
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
import {
  KeyFinderFunc,
  VerificationError,
  VerificationPolicy,
} from '@sigstore/verify';

import type { MakeFetchHappenOptions } from 'make-fetch-happen';

type Retry = MakeFetchHappenOptions['retry'];

type FetchOptions = {
  retry?: Retry;
  timeout?: number | undefined;
};

type KeySelector = (hint: string) => string | Buffer | undefined;

export type SignOptions = {
  fulcioURL?: string;
  identityProvider?: IdentityProvider;
  identityToken?: string;
  rekorURL?: string;
  tlogUpload?: boolean;
  tsaServerURL?: string;
  legacyCompatibility?: boolean;
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
  tufForceCache?: boolean;
} & FetchOptions;

export const DEFAULT_RETRY: Retry = { retries: 2 };
export const DEFAULT_TIMEOUT = 5000;

type BundleType = 'messageSignature' | 'dsseEnvelope';

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
      return new DSSEBundleBuilder({
        ...bundlerOptions,
        certificateChain: options.legacyCompatibility,
      });
  }
}

// Translates the public KeySelector type into the KeyFinderFunc type needed by
// the verifier.
export function createKeyFinder(keySelector: KeySelector): KeyFinderFunc {
  return (hint: string) => {
    const key = keySelector(hint);

    if (!key) {
      throw new VerificationError({
        code: 'PUBLIC_KEY_ERROR',
        message: `key not found: ${hint}`,
      });
    }

    return {
      publicKey: crypto.createPublicKey(key),
      validFor: () => true,
    };
  };
}

export function createVerificationPolicy(
  options: VerifyOptions
): VerificationPolicy {
  const policy: VerificationPolicy = {};

  const san =
    options.certificateIdentityEmail || options.certificateIdentityURI;
  if (san) {
    policy.subjectAlternativeName = san;
  }

  if (options.certificateIssuer) {
    policy.extensions = { issuer: options.certificateIssuer };
  }

  return policy;
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
    /* istanbul ignore next */
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
        entryType: options.legacyCompatibility ? 'intoto' : 'dsse',
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
