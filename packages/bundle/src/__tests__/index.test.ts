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
  BUNDLE_V01_MEDIA_TYPE,
  BUNDLE_V02_MEDIA_TYPE,
  Bundle,
  BundleLatest,
  BundleV01,
  BundleWithCertificateChain,
  BundleWithDsseEnvelope,
  BundleWithMessageSignature,
  BundleWithPublicKey,
  Envelope,
  InclusionProof,
  MessageSignature,
  PublicKeyIdentifier,
  RFC3161SignedTimestamp,
  SerializedBundle,
  SerializedEnvelope,
  Signature,
  TLogEntryWithInclusionPromise,
  TLogEntryWithInclusionProof,
  TimestampVerificationData,
  TransparencyLogEntry,
  ValidationError,
  VerificationMaterial,
  X509Certificate,
  X509CertificateChain,
  assertBundle,
  assertBundleLatest,
  assertBundleV01,
  bundleFromJSON,
  bundleToJSON,
  envelopeFromJSON,
  envelopeToJSON,
  isBundleV01,
  isBundleWithCertificateChain,
  isBundleWithDsseEnvelope,
  isBundleWithMessageSignature,
  isBundleWithPublicKey,
  toDSSEBundle,
  toMessageSignatureBundle,
} from '../index';

describe('public interface', () => {
  it('exports types', () => {
    const bundle: Bundle = fromPartial({});
    expect(bundle).toBeDefined();

    const bundleV01: BundleV01 = fromPartial({});
    expect(bundleV01).toBeDefined();

    const bundleLatest: BundleLatest = fromPartial({});
    expect(bundleLatest).toBeDefined();

    const bundleWithCertificateChain: BundleWithCertificateChain = fromPartial(
      {}
    );
    expect(bundleWithCertificateChain).toBeDefined();

    const bundleWithDsseEnvelope: BundleWithDsseEnvelope = fromPartial({});
    expect(bundleWithDsseEnvelope).toBeDefined();

    const bundleWithMessageSignature: BundleWithMessageSignature = fromPartial(
      {}
    );
    expect(bundleWithMessageSignature).toBeDefined();

    const bundleWithPublicKey: BundleWithPublicKey = fromPartial({});
    expect(bundleWithPublicKey).toBeDefined();

    const envelope: Envelope = fromPartial({});
    expect(envelope).toBeDefined();

    const inclusionProof: InclusionProof = fromPartial({});
    expect(inclusionProof).toBeDefined();

    const messageSignature: MessageSignature = fromPartial({});
    expect(messageSignature).toBeDefined();

    const publicKeyIdentifier: PublicKeyIdentifier = fromPartial({});
    expect(publicKeyIdentifier).toBeDefined();

    const rfc3161SignedTimestamp: RFC3161SignedTimestamp = fromPartial({});
    expect(rfc3161SignedTimestamp).toBeDefined();

    const serializedBundle: SerializedBundle = fromPartial({});
    expect(serializedBundle).toBeDefined();

    const serializedEnvelope: SerializedEnvelope = fromPartial({});
    expect(serializedEnvelope).toBeDefined();

    const signature: Signature = fromPartial({});
    expect(signature).toBeDefined();

    const timestampVerificationData: TimestampVerificationData = fromPartial(
      {}
    );
    expect(timestampVerificationData).toBeDefined();

    const transparencyLogEntry: TransparencyLogEntry = fromPartial({});
    expect(transparencyLogEntry).toBeDefined();

    const tlogEntryWithProof: TLogEntryWithInclusionProof = fromPartial({});
    expect(tlogEntryWithProof).toBeDefined();

    const tlogEntryWithPromise: TLogEntryWithInclusionPromise = fromPartial({});
    expect(tlogEntryWithPromise).toBeDefined();

    const verificationMaterial: VerificationMaterial = fromPartial({});
    expect(verificationMaterial).toBeDefined();

    const x509Certificate: X509Certificate = fromPartial({});
    expect(x509Certificate).toBeDefined();

    const x509CertificateChain: X509CertificateChain = fromPartial({});
    expect(x509CertificateChain).toBeDefined();
  });

  it('exports bundle construction functions', () => {
    expect(toDSSEBundle).toBeDefined();
    expect(toMessageSignatureBundle).toBeDefined();
  });

  it('exports type guard functions', () => {
    expect(isBundleWithCertificateChain).toBeDefined();
    expect(isBundleWithDsseEnvelope).toBeDefined();
    expect(isBundleWithMessageSignature).toBeDefined();
    expect(isBundleWithPublicKey).toBeDefined();
    expect(isBundleV01).toBeDefined();
  });

  it('exports type assertion functions', () => {
    expect(assertBundle).toBeDefined();
    expect(assertBundleLatest).toBeDefined();
    expect(assertBundleV01).toBeDefined();
  });

  it('exports serialization functions', () => {
    expect(bundleFromJSON).toBeDefined();
    expect(bundleToJSON).toBeDefined();
    expect(envelopeFromJSON).toBeDefined();
    expect(envelopeToJSON).toBeDefined();
  });

  it('exports constants', () => {
    expect(BUNDLE_V01_MEDIA_TYPE).toBeDefined();
    expect(BUNDLE_V02_MEDIA_TYPE).toBeDefined();
  });

  it('exports errors', () => {
    expect(ValidationError).toBeInstanceOf(Object);
  });
});
