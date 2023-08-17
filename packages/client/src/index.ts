/*
Copyright 2022 The Sigstore Authors.

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
export { ValidationError } from '@sigstore/bundle';
export { InternalError } from '@sigstore/sign';
export { TUFError } from '@sigstore/tuf';
export { DEFAULT_FULCIO_URL, DEFAULT_REKOR_URL } from './config';
export { PolicyError, VerificationError } from './error';
export { attest, createVerifier, sign, verify } from './sigstore';

export type { SerializedBundle as Bundle } from '@sigstore/bundle';
export type { IdentityProvider } from '@sigstore/sign';
export type { SignOptions, VerifyOptions } from './config';
export type { BundleVerifier } from './sigstore';
