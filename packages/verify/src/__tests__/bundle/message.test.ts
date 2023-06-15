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
import { crypto as core } from '@sigstore/core';
import { HashAlgorithm } from '@sigstore/protobuf-specs';
import crypto from 'crypto';
import { MessageSignatureContent } from '../../bundle/message';

import type { MessageSignature } from '@sigstore/bundle';

describe('MessageSignatureContent', () => {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const message = Buffer.from('message');
  const messageDigest = core.hash(message);

  const messageSignature: MessageSignature = {
    messageDigest: { digest: messageDigest, algorithm: HashAlgorithm.SHA2_256 },
    signature: crypto.sign(null, message, key.privateKey),
  };

  const subject = new MessageSignatureContent(messageSignature, message);

  describe('#compareDigest', () => {
    describe('when the digest does NOT match the message hash', () => {
      it('returns false', () => {
        expect(subject.compareDigest(Buffer.from(''))).toBe(false);
      });
    });

    describe('when the digest matches the message hash', () => {
      it('returns true', () => {
        expect(subject.compareDigest(messageDigest)).toBe(true);
      });
    });
  });

  describe('#compareSignature', () => {
    describe('when the signature does NOT match the message signature', () => {
      it('returns false', () => {
        expect(subject.compareSignature(Buffer.from(''))).toBe(false);
      });
    });

    describe('when the signature matches the message signature', () => {
      it('returns true', () => {
        expect(subject.compareSignature(messageSignature.signature)).toBe(true);
      });
    });
  });

  describe('#verifySignature', () => {
    describe('when the signature is NOT valid', () => {
      const invalidKey = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
      });

      it('returns false', () => {
        expect(subject.verifySignature(invalidKey.publicKey)).toBe(false);
      });
    });

    describe('when the signature is valid', () => {
      it('returns true', () => {
        expect(subject.verifySignature(key.publicKey)).toBe(true);
      });
    });
  });
});
