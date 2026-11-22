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
  const messageDigest = core.digest('sha256', message);

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

  describe('#compareSignedDigest', () => {
    describe('when the digest does NOT match the message hash', () => {
      it('returns false', () => {
        expect(subject.compareSignedDigest(Buffer.from(''))).toBe(false);
      });
    });

    describe('when the digest matches the message hash', () => {
      it('returns true', () => {
        expect(subject.compareSignedDigest(messageDigest)).toBe(true);
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

    describe('with SHA2_256 hash algorithm', () => {
      const message256 = Buffer.from('message256');
      const messageDigest256 = core.digest('sha256', message256);
      const messageSignature256: MessageSignature = {
        messageDigest: {
          digest: messageDigest256,
          algorithm: HashAlgorithm.SHA2_256,
        },
        signature: crypto.sign('sha256', message256, key.privateKey),
      };
      const subject256 = new MessageSignatureContent(
        messageSignature256,
        message256
      );

      it('verifies signature with explicit hash algorithm', () => {
        expect(subject256.verifySignature(key.publicKey)).toBe(true);
      });
    });

    describe('with SHA2_512 hash algorithm', () => {
      const message512 = Buffer.from('message512');
      const messageDigest512 = core.digest('sha512', message512);
      const messageSignature512: MessageSignature = {
        messageDigest: {
          digest: messageDigest512,
          algorithm: HashAlgorithm.SHA2_512,
        },
        signature: crypto.sign('sha512', message512, key.privateKey),
      };
      const subject512 = new MessageSignatureContent(
        messageSignature512,
        message512
      );

      it('verifies signature with explicit hash algorithm', () => {
        expect(subject512.verifySignature(key.publicKey)).toBe(true);
      });
    });

    describe('when using HASH_ALGORITHM_UNSPECIFIED', () => {
      const unspecifiedMessageSignature: MessageSignature = {
        messageDigest: {
          digest: messageDigest,
          algorithm: HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED,
        },
        signature: crypto.sign(null, message, key.privateKey),
      };
      const unspecifiedSubject = new MessageSignatureContent(
        unspecifiedMessageSignature,
        message
      );

      it('defaults to sha256 and returns true for valid signature', () => {
        expect(unspecifiedSubject.verifySignature(key.publicKey)).toBe(true);
      });
    });
  });
});

describe('MessageSignatureContent with Ed25519 keys', () => {
  const key = crypto.generateKeyPairSync('ed25519');
  const message = Buffer.from('artifact contents');

  const build = (artifact: Buffer, signature: Buffer, alg: HashAlgorithm) =>
    new MessageSignatureContent(
      {
        messageDigest: {
          digest: core.digest('sha256', artifact),
          algorithm: alg,
        },
        signature,
      },
      artifact
    );

  const signature = crypto.sign(null, message, key.privateKey);

  it.each([
    HashAlgorithm.SHA2_256,
    HashAlgorithm.SHA2_384,
    HashAlgorithm.SHA2_512,
    HashAlgorithm.HASH_ALGORITHM_UNSPECIFIED,
  ])('verifies a signature over the full artifact (digest alg %s)', (alg) => {
    expect(build(message, signature, alg).verifySignature(key.publicKey)).toBe(
      true
    );
  });

  it('rejects a tampered artifact', () => {
    expect(
      build(
        Buffer.from('other contents'),
        signature,
        HashAlgorithm.SHA2_256
      ).verifySignature(key.publicKey)
    ).toBe(false);
  });

  it('rejects a signature over the digest instead of the artifact', () => {
    const digestSig = crypto.sign(
      null,
      core.digest('sha256', message),
      key.privateKey
    );
    expect(
      build(message, digestSig, HashAlgorithm.SHA2_256).verifySignature(
        key.publicKey
      )
    ).toBe(false);
  });

  it('rejects verification when no artifact is available', () => {
    const subject = new MessageSignatureContent(
      {
        messageDigest: {
          digest: core.digest('sha256', message),
          algorithm: HashAlgorithm.SHA2_256,
        },
        signature,
      },
      undefined as unknown as Buffer
    );
    expect(subject.verifySignature(key.publicKey)).toBe(false);
  });

  describe('when the artifact is empty', () => {
    const empty = Buffer.alloc(0);

    it('verifies a signature over the empty artifact', () => {
      const emptySig = crypto.sign(null, empty, key.privateKey);
      expect(
        build(empty, emptySig, HashAlgorithm.SHA2_256).verifySignature(
          key.publicKey
        )
      ).toBe(true);
    });

    it('rejects a signature over different contents', () => {
      expect(
        build(empty, signature, HashAlgorithm.SHA2_256).verifySignature(
          key.publicKey
        )
      ).toBe(false);
    });
  });

  it('identity point key is rejected', () => {
    const smallOrderKey = crypto.createPublicKey({
      key: Buffer.from(
        '302a300506032b6570032100' + '01' + '00'.repeat(31),
        'hex'
      ),
      format: 'der',
      type: 'spki',
    });
    const identitySignature = Buffer.from(
      '01' + '00'.repeat(31) + '00'.repeat(32),
      'hex'
    );
    expect(
      build(message, identitySignature, HashAlgorithm.SHA2_256).verifySignature(
        smallOrderKey
      )
    ).toBe(false);
  });
});
