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
import * as sigstore from './types/sigstore';
import { Verifier } from './verify';

export async function sign(
  payload: Buffer,
  /* istanbul ignore next */
  options: config.SignOptions = {}
): Promise<sigstore.SerializedBundle> {
  const notary = config.notary({ bundleType: 'messageSignature', ...options });
  const bundle = await notary.notarize({ data: payload });
  return sigstore.Bundle.toJSON(bundle) as sigstore.SerializedBundle;
}

export async function attest(
  payload: Buffer,
  payloadType: string,
  /* istanbul ignore next */
  options: config.SignOptions = {}
): Promise<sigstore.SerializedBundle> {
  const notary = config.notary({ bundleType: 'dsseEnvelope', ...options });
  const bundle = await notary.notarize({ data: payload, type: payloadType });
  return sigstore.Bundle.toJSON(bundle) as sigstore.SerializedBundle;
}

export async function verify(
  bundle: sigstore.SerializedBundle,
  payload?: Buffer,
  /* istanbul ignore next */
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
    /* istanbul ignore next - not covering options default */
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
export type { Provider as IdentityProvider } from './identity';
export * as utils from './sigstore-utils';
export type {
  SerializedBundle as Bundle,
  SerializedEnvelope as Envelope,
} from './types/sigstore';
export { tufUtils as tuf };
export const DEFAULT_FULCIO_URL = config.DEFAULT_FULCIO_URL;
export const DEFAULT_REKOR_URL = config.DEFAULT_REKOR_URL;
