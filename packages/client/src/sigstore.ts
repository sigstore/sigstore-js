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
  SerializedBundle,
  bundleFromJSON,
  bundleToJSON,
} from '@sigstore/bundle';
import * as tuf from '@sigstore/tuf';
import * as config from './config';
import { Verifier } from './verify';

export async function sign(
  payload: Buffer,
  options: config.SignOptions = {}
): Promise<SerializedBundle> {
  const bundler = config.createBundleBuilder('messageSignature', options);
  const bundle = await bundler.create({ data: payload });
  return bundleToJSON(bundle);
}

export async function attest(
  payload: Buffer,
  payloadType: string,
  options: config.SignOptions = {}
): Promise<SerializedBundle> {
  const bundler = config.createBundleBuilder('dsseEnvelope', options);
  const bundle = await bundler.create({ data: payload, type: payloadType });
  return bundleToJSON(bundle);
}

export async function verify(
  bundle: SerializedBundle,
  payload?: Buffer,
  options: config.VerifyOptions = {}
): Promise<void> {
  const trustedRoot = await tuf.getTrustedRoot({
    mirrorURL: options.tufMirrorURL,
    rootPath: options.tufRootPath,
    cachePath: options.tufCachePath,
    retry: options.retry ?? config.DEFAULT_RETRY,
    timeout: options.timeout ?? config.DEFAULT_TIMEOUT,
  });
  const verifier = new Verifier(trustedRoot, options.keySelector);

  const deserializedBundle = bundleFromJSON(bundle);
  const opts = config.artifactVerificationOptions(options);
  return verifier.verify(deserializedBundle, opts, payload);
}

export interface BundleVerifier {
  verify(bundle: SerializedBundle): void;
}

export async function createVerifier(
  options: config.CreateVerifierOptions
): Promise<BundleVerifier> {
  const trustedRoot = await tuf.getTrustedRoot({
    mirrorURL: options.tufMirrorURL,
    rootPath: options.tufRootPath,
    cachePath: options.tufCachePath,
    retry: options.retry ?? config.DEFAULT_RETRY,
    timeout: options.timeout ?? config.DEFAULT_TIMEOUT,
  });
  const verifier = new Verifier(trustedRoot, options.keySelector);
  const verifyOpts = config.artifactVerificationOptions(options);

  return {
    verify: (bundle: SerializedBundle): void => {
      const deserializedBundle = bundleFromJSON(bundle);
      return verifier.verify(deserializedBundle, verifyOpts);
    },
  };
}

const tufUtils = {
  client: (options: config.TUFOptions = {}): Promise<tuf.TUF> => {
    return tuf.initTUF({
      mirrorURL: options.tufMirrorURL,
      rootPath: options.tufRootPath,
      cachePath: options.tufCachePath,
      retry: options.retry,
      timeout: options.timeout,
    });
  },

  /*
   * @deprecated Use tufUtils.client instead.
   */
  getTarget: (
    path: string,
    options: config.TUFOptions = {}
  ): Promise<string> => {
    return tuf
      .initTUF({
        mirrorURL: options.tufMirrorURL,
        rootPath: options.tufRootPath,
        cachePath: options.tufCachePath,
        retry: options.retry,
        timeout: options.timeout,
      })
      .then((t) => t.getTarget(path));
  },
};

export { ValidationError } from '@sigstore/bundle';
export type {
  SerializedBundle as Bundle,
  SerializedEnvelope as Envelope,
} from '@sigstore/bundle';
export type { TUF } from '@sigstore/tuf';
export type { SignOptions, VerifyOptions } from './config';
export { InternalError, PolicyError, VerificationError } from './error';
export { tufUtils as tuf };
export const DEFAULT_FULCIO_URL = config.DEFAULT_FULCIO_URL;
export const DEFAULT_REKOR_URL = config.DEFAULT_REKOR_URL;
