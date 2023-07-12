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
export {
  BUNDLE_V01_MEDIA_TYPE,
  BUNDLE_V02_MEDIA_TYPE,
  isBundleWithCertificateChain,
  isBundleWithDsseEnvelope,
  isBundleWithMessageSignature,
  isBundleWithPublicKey,
} from './bundle';
export { ValidationError } from './error';
export { bundleFromJSON, bundleToJSON } from './serialized';
export {
  assertBundle,
  assertBundleLatest,
  assertBundleV01,
  isBundleV01,
} from './validate';

export type {
  Envelope,
  PublicKeyIdentifier,
  RFC3161SignedTimestamp,
  Signature,
  TimestampVerificationData,
  X509Certificate,
  X509CertificateChain,
} from '@sigstore/protobuf-specs';
export type {
  Bundle,
  BundleLatest,
  BundleV01,
  BundleWithCertificateChain,
  BundleWithDsseEnvelope,
  BundleWithMessageSignature,
  BundleWithPublicKey,
  InclusionProof,
  MessageSignature,
  TLogEntryWithInclusionPromise,
  TLogEntryWithInclusionProof,
  TransparencyLogEntry,
  VerificationMaterial,
} from './bundle';
export type { SerializedBundle, SerializedEnvelope } from './serialized';
