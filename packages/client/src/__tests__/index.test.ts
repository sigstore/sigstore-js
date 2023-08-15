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
import { IdentityProvider, sigstore } from '..';

describe('sigstore', () => {
  // This test is a bit of a hack to ensure that the types are exported
  it('exports sigstore types', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bundle: sigstore.Bundle = {} as any;
    expect(bundle).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const envelope: sigstore.Envelope = {} as any;
    expect(envelope).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const signOptions: sigstore.SignOptions = {} as any;
    expect(signOptions).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const verifyOptions: sigstore.VerifyOptions = {} as any;
    expect(verifyOptions).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const identityProvider: IdentityProvider = {} as any;
    expect(identityProvider).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bundleVerifier: sigstore.BundleVerifier = {} as any;
    expect(bundleVerifier).toBeDefined();
  });

  it('exports sigstore core functions', async () => {
    expect(sigstore.attest).toBeInstanceOf(Function);
    expect(sigstore.sign).toBeInstanceOf(Function);
    expect(sigstore.verify).toBeInstanceOf(Function);
    expect(sigstore.createVerifier).toBeInstanceOf(Function);
  });

  it('exports sigstore utils', () => {
    expect(sigstore.utils).toBeDefined();
    expect(sigstore.utils.createDSSEEnvelope).toBeInstanceOf(Function);
    expect(sigstore.utils.createRekorEntry).toBeInstanceOf(Function);
  });

  it('exports errors', () => {
    expect(sigstore.InternalError).toBeInstanceOf(Object);
    expect(sigstore.PolicyError).toBeInstanceOf(Object);
    expect(sigstore.VerificationError).toBeInstanceOf(Object);
    expect(sigstore.ValidationError).toBeInstanceOf(Object);
  });
});
