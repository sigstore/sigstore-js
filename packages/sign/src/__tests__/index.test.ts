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
  CIContextProvider,
  DSSENotary,
  FulcioSigner,
  InternalError,
  MessageNotary,
  RekorWitness,
  TSAWitness,
} from '..';

import type {
  Affidavit,
  Artifact,
  Bundle,
  Endorsement,
  FulcioSignerOptions,
  IdentityProvider,
  Notary,
  NotaryOptions,
  RekorWitnessOptions,
  Signatory,
  SignatureBundle,
  TSAWitnessOptions,
  Witness,
} from '..';

// This test is a bit of a hack to ensure that the types are exported
it('exports types', async () => {
  const affidavit: Affidavit = fromPartial({});
  expect(affidavit).toBeDefined();

  const artifact: Artifact = fromPartial({});
  expect(artifact).toBeDefined();

  const bundle: Bundle = fromPartial({});
  expect(bundle).toBeDefined();

  const endorsement: Endorsement = fromPartial({});
  expect(endorsement).toBeDefined();

  const signatureBundle: SignatureBundle = fromPartial({});
  expect(signatureBundle).toBeDefined();

  const notary: Notary = fromPartial({});
  expect(notary).toBeDefined();

  const notaryOptions: NotaryOptions = fromPartial({});
  expect(notaryOptions).toBeDefined();

  const witness: Witness = fromPartial({});
  expect(witness).toBeDefined();

  const rekorWitnessOptions: RekorWitnessOptions = fromPartial({});
  expect(rekorWitnessOptions).toBeDefined();

  const tsaWitnessOptions: TSAWitnessOptions = fromPartial({});
  expect(tsaWitnessOptions).toBeDefined();

  const signatory: Signatory = fromPartial({});
  expect(signatory).toBeDefined();

  const fulcioSignerOptions: FulcioSignerOptions = fromPartial({});
  expect(fulcioSignerOptions).toBeDefined();

  const identityProvider: IdentityProvider = fromPartial({});
  expect(identityProvider).toBeDefined();
});

it('exports classes', () => {
  expect(CIContextProvider).toBeInstanceOf(Function);
  expect(DSSENotary).toBeInstanceOf(Function);
  expect(MessageNotary).toBeInstanceOf(Function);
  expect(FulcioSigner).toBeInstanceOf(Function);
  expect(RekorWitness).toBeInstanceOf(Function);
  expect(TSAWitness).toBeInstanceOf(Function);
});

it('exports errors', () => {
  expect(InternalError).toBeInstanceOf(Function);
});
