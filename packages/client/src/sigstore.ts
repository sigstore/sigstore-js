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
import * as tuf from '@sigstore/tuf';
import * as config from './config';
import { Signer } from './sign';
import * as sigstore from './types/sigstore';
import { Verifier } from './verify';

export async function sign(
  payload: Buffer,
  options: config.SignOptions = {}
): Promise<sigstore.SerializedBundle> {
  const ca = config.createCAClient(options);
  const tlog = config.createTLogClient(options);
  const idps = config.identityProviders(options);
  const signer = new Signer({
    ca,
    tlog,
    identityProviders: options.identityProvider
      ? [options.identityProvider]
      : idps,
    tlogUpload: options.tlogUpload,
  });

  const bundle = await signer.signBlob(payload);
  return sigstore.bundleToJSON(bundle) as sigstore.SerializedBundle;
}

export async function attest(
  payload: Buffer,
  payloadType: string,
  options: config.SignOptions = {}
): Promise<sigstore.SerializedBundle> {
  const ca = config.createCAClient(options);
  const tlog = config.createTLogClient(options);
  const tsa = config.createTSAClient(options);
  const idps = config.identityProviders(options);
  const signer = new Signer({
    ca,
    tlog,
    tsa,
    identityProviders: options.identityProvider
      ? [options.identityProvider]
      : idps,
    tlogUpload: options.tlogUpload,
  });

  const bundle = await signer.signAttestation(payload, payloadType);
  return sigstore.bundleToJSON(bundle) as sigstore.SerializedBundle;
}

export async function verify(
  bundle: sigstore.SerializedBundle,
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

  const deserializedBundle = sigstore.bundleFromJSON(bundle);
  const opts = config.artifactVerificationOptions(options);
  return verifier.verify(deserializedBundle, opts, payload);
}

export interface BundleVerifier {
  verify(bundle: sigstore.SerializedBundle): void;
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
    verify: (bundle: sigstore.SerializedBundle): void => {
      const deserializedBundle = sigstore.bundleFromJSON(bundle);
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

export type { TUF } from '@sigstore/tuf';
export type { SignOptions, VerifyOptions } from './config';
export {
  InternalError,
  PolicyError,
  ValidationError,
  VerificationError,
} from './error';
export * as utils from './sigstore-utils';
export type {
  SerializedBundle as Bundle,
  SerializedEnvelope as Envelope,
} from './types/sigstore';
export { tufUtils as tuf };
export const DEFAULT_FULCIO_URL = config.DEFAULT_FULCIO_URL;
export const DEFAULT_REKOR_URL = config.DEFAULT_REKOR_URL;
