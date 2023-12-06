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
  KeyFinderFunc,
  PolicyError,
  SignedEntity,
  Signer,
  TrustMaterial,
  VerificationError,
  Verifier,
  VerifierOptions,
  toSignedEntity,
  toTrustMaterial,
} from '..';

it('exports classes', () => {
  expect(Verifier).toBeDefined();
  expect(VerificationError).toBeDefined();
  expect(PolicyError).toBeDefined();
});

it('exports functions', () => {
  expect(toSignedEntity).toBeInstanceOf(Function);
  expect(toTrustMaterial).toBeInstanceOf(Function);
});

it('exports types', async () => {
  const verifierOptions: VerifierOptions = fromPartial({});
  expect(verifierOptions).toBeDefined();

  const signedEntity: SignedEntity = fromPartial({});
  expect(signedEntity).toBeDefined();

  const signer: Signer = fromPartial({});
  expect(signer).toBeDefined();

  const trustMaterial: TrustMaterial = fromPartial({});
  expect(trustMaterial).toBeDefined();

  const keyFinderFunc: KeyFinderFunc = fromPartial({});
  expect(keyFinderFunc).toBeDefined();
});
