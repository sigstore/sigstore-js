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
import {
  Verifier,
  VerifierOptions,
  toSignedEntity,
  toTrustMaterial,
} from '@sigstore/verify';
import * as config from './config';

export async function sign(
  payload: Buffer,
  /* istanbul ignore next */
  options: config.SignOptions = {}
): Promise<SerializedBundle> {
  const bundler = config.createBundleBuilder('messageSignature', options);
  const bundle = await bundler.create({ data: payload });
  return bundleToJSON(bundle);
}

export async function attest(
  payload: Buffer,
  payloadType: string,
  /* istanbul ignore next */
  options: config.SignOptions = {}
): Promise<SerializedBundle> {
  const bundler = config.createBundleBuilder('dsseEnvelope', options);
  const bundle = await bundler.create({ data: payload, type: payloadType });
  return bundleToJSON(bundle);
}

export async function verify(
  bundle: SerializedBundle,
  options?: config.VerifyOptions
): Promise<void>;
export async function verify(
  bundle: SerializedBundle,
  data: Buffer,
  options?: config.VerifyOptions
): Promise<void>;
export async function verify(
  bundle: SerializedBundle,
  dataOrOptions?: Buffer | config.VerifyOptions,
  options?: config.VerifyOptions
): Promise<void> {
  let data: Buffer | undefined;
  if (Buffer.isBuffer(dataOrOptions)) {
    data = dataOrOptions;
  } else {
    options = dataOrOptions;
  }

  return createVerifier(options).then((verifier) =>
    verifier.verify(bundle, data)
  );
}

export interface BundleVerifier {
  verify(bundle: SerializedBundle, data?: Buffer): void;
}

export async function createVerifier(
  /* istanbul ignore next */
  options: config.VerifyOptions = {}
): Promise<BundleVerifier> {
  const trustedRoot = await tuf.getTrustedRoot({
    mirrorURL: options.tufMirrorURL,
    rootPath: options.tufRootPath,
    cachePath: options.tufCachePath,
    retry: options.retry ?? config.DEFAULT_RETRY,
    timeout: options.timeout ?? config.DEFAULT_TIMEOUT,
  });

  const keyFinder = options.keySelector
    ? config.createKeyFinder(options.keySelector)
    : undefined;
  const trustMaterial = toTrustMaterial(trustedRoot, keyFinder);

  const verifierOptions: VerifierOptions = {
    ctlogThreshold: options.ctLogThreshold,
    tlogThreshold: options.tlogThreshold,
  };
  const verifier = new Verifier(trustMaterial, verifierOptions);
  const policy = config.createVerificationPolicy(options);

  return {
    verify: (bundle: SerializedBundle, payload?: Buffer): void => {
      const deserializedBundle = bundleFromJSON(bundle);
      const signedEntity = toSignedEntity(deserializedBundle, payload);
      verifier.verify(signedEntity, policy);
      return;
    },
  };
}
