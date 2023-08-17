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
import * as sigstore from '..';

// This test is a bit of a hack to ensure that the types are exported
it('exports sigstore types', async () => {
  const bundle: sigstore.Bundle = fromPartial({});
  expect(bundle).toBeDefined();

  const signOptions: sigstore.SignOptions = fromPartial({});
  expect(signOptions).toBeDefined();

  const verifyOptions: sigstore.VerifyOptions = fromPartial({});
  expect(verifyOptions).toBeDefined();

  const identityProvider: sigstore.IdentityProvider = fromPartial({});
  expect(identityProvider).toBeDefined();

  const bundleVerifier: sigstore.BundleVerifier = fromPartial({});
  expect(bundleVerifier).toBeDefined();
});

it('exports sigstore core functions', async () => {
  expect(sigstore.attest).toBeInstanceOf(Function);
  expect(sigstore.sign).toBeInstanceOf(Function);
  expect(sigstore.verify).toBeInstanceOf(Function);
  expect(sigstore.createVerifier).toBeInstanceOf(Function);
});

it('exports errors', () => {
  expect(sigstore.InternalError).toBeInstanceOf(Object);
  expect(sigstore.PolicyError).toBeInstanceOf(Object);
  expect(sigstore.VerificationError).toBeInstanceOf(Object);
  expect(sigstore.ValidationError).toBeInstanceOf(Object);
  expect(sigstore.TUFError).toBeInstanceOf(Object);
});

it('exports constants', () => {
  expect(sigstore.DEFAULT_FULCIO_URL).toBeDefined();
  expect(sigstore.DEFAULT_REKOR_URL).toBeDefined();
});
