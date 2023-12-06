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
import { bundleFromJSON } from '@sigstore/bundle';
import { crypto } from '@sigstore/core';
import { PublicKeyDetails } from '@sigstore/protobuf-specs';
import { fromPartial } from '@total-typescript/shoehorn';
import { toSignedEntity } from '../bundle';
import { VerificationError } from '../error';
import { TrustMaterial, toTrustMaterial } from '../trust';
import { Verifier } from '../verifier';
import bundles from './__fixtures__/bundles/v01';
import { trustedRoot } from './__fixtures__/trust';

describe('Verifier', () => {
  describe('constructor', () => {
    const trustMaterial: TrustMaterial = fromPartial({});

    it('should create a new instance', () => {
      const verifier = new Verifier(trustMaterial);
      expect(verifier).toBeDefined();
    });
  });

  describe('#verify', () => {
    const publicKey = crypto.createPublicKey(bundles.signature.publicKey);

    const keys = {
      '9a76331edc1cfd3933040996615b1c06adbe6f9b4f11df4106dcceb66e3bdb1b': {
        rawBytes: publicKey.export({ type: 'spki', format: 'der' }),
        keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
        validFor: { start: new Date(0) },
      },
    };
    const trustMaterial = toTrustMaterial(trustedRoot, keys);
    const subject = new Verifier(trustMaterial);

    describe('when the certificate-signed message signature bundle is valid', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
      const signedEntity = toSignedEntity(bundle, bundles.signature.artifact);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the key-signed message signature bundle is valid', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withPublicKey);
      const signedEntity = toSignedEntity(bundle, bundles.signature.artifact);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the certificate-signed DSSE bundle is valid', () => {
      const bundle = bundleFromJSON(bundles.dsse.valid.withSigningCert);
      const signedEntity = toSignedEntity(bundle);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the bundle contains duplicate TLog entries', () => {
      const bundle = bundleFromJSON(bundles.signature.invalid.duplicateTLog);
      const signedEntity = toSignedEntity(bundle, bundles.signature.artifact);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'TIMESTAMP_ERROR'
        );
      });
    });

    describe('when the tlog timestamp threshold is not met', () => {
      const subject = new Verifier(trustMaterial, { tlogThreshold: 2 });
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
      const signedEntity = toSignedEntity(bundle, bundles.signature.artifact);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'TIMESTAMP_ERROR'
        );
      });
    });

    describe('when the tsa timestamp threshold is not met', () => {
      const subject = new Verifier(trustMaterial, { tsaThreshold: 2 });
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
      const signedEntity = toSignedEntity(bundle, bundles.signature.artifact);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'TIMESTAMP_ERROR'
        );
      });
    });

    describe('when the ctlog threshold is not met', () => {
      const subject = new Verifier(trustMaterial, { ctlogThreshold: 2 });
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
      const signedEntity = toSignedEntity(bundle, bundles.signature.artifact);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'CERTIFICATE_ERROR'
        );
      });
    });

    describe('when the bundle signature cannot be verified', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
      const signedEntity = toSignedEntity(
        bundle,
        Buffer.from('not the artifact')
      );

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'SIGNATURE_ERROR'
        );
      });
    });
  });
});
