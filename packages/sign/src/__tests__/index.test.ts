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
import { fromPartial } from '@total-typescript/shoehorn';
import {
  bundleBuilderFromSigningConfig,
  CIContextProvider,
  DEFAULT_FULCIO_URL,
  DEFAULT_REKOR_URL,
  DSSEBundleBuilder,
  FulcioSigner,
  InternalError,
  MessageSignatureBundleBuilder,
  RekorWitness,
  TSAWitness,
} from '..';

import type {
  Artifact,
  Bundle,
  BundleBuilder,
  BundleBuilderOptions,
  FulcioSignerOptions,
  IdentityProvider,
  RekorWitnessOptions,
  Signature,
  SignatureBundle,
  Signer,
  TSAWitnessOptions,
  VerificationMaterial,
  Witness,
} from '..';

// This test is a bit of a hack to ensure that the types are exported
it('exports types', async () => {
  const verificationMaterial: VerificationMaterial = fromPartial({});
  expect(verificationMaterial).toBeDefined();

  const artifact: Artifact = fromPartial({});
  expect(artifact).toBeDefined();

  const bundle: Bundle = fromPartial({});
  expect(bundle).toBeDefined();

  const signature: Signature = fromPartial({});
  expect(signature).toBeDefined();

  const signatureBundle: SignatureBundle = fromPartial({});
  expect(signatureBundle).toBeDefined();

  const bundler: BundleBuilder = fromPartial({});
  expect(bundler).toBeDefined();

  const bundlerOptions: BundleBuilderOptions = fromPartial({});
  expect(bundlerOptions).toBeDefined();

  const witness: Witness = fromPartial({});
  expect(witness).toBeDefined();

  const rekorWitnessOptions: RekorWitnessOptions = fromPartial({});
  expect(rekorWitnessOptions).toBeDefined();

  const tsaWitnessOptions: TSAWitnessOptions = fromPartial({});
  expect(tsaWitnessOptions).toBeDefined();

  const signer: Signer = fromPartial({});
  expect(signer).toBeDefined();

  const fulcioSignerOptions: FulcioSignerOptions = fromPartial({});
  expect(fulcioSignerOptions).toBeDefined();

  const identityProvider: IdentityProvider = fromPartial({});
  expect(identityProvider).toBeDefined();
});

it('exports classes', () => {
  expect(CIContextProvider).toBeInstanceOf(Function);
  expect(DSSEBundleBuilder).toBeInstanceOf(Function);
  expect(MessageSignatureBundleBuilder).toBeInstanceOf(Function);
  expect(FulcioSigner).toBeInstanceOf(Function);
  expect(RekorWitness).toBeInstanceOf(Function);
  expect(TSAWitness).toBeInstanceOf(Function);
});

it('exports functions', () => {
  expect(bundleBuilderFromSigningConfig).toBeInstanceOf(Function);
});

it('exports errors', () => {
  expect(InternalError).toBeInstanceOf(Function);
});

it('exports constants', () => {
  expect(DEFAULT_FULCIO_URL).toBeDefined();
  expect(DEFAULT_REKOR_URL).toBeDefined();
});
