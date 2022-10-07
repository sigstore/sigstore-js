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
import {
  generateKeyPair,
  hash,
  randomBytes,
  signBlob,
  verifyBlob,
} from './crypto';

describe('generateKeyPair', () => {
  it('generates an EC keypair', () => {
    const keypair = generateKeyPair();

    expect(keypair.privateKey).toBeDefined();
    expect(keypair.privateKey.asymmetricKeyType).toBe('ec');

    expect(keypair.publicKey).toBeDefined();
    expect(keypair.publicKey.asymmetricKeyType).toBe('ec');
  });
});

describe('hash', () => {
  it('returns the SHA256 digest of the blob', () => {
    const blob = Buffer.from('hello world');
    const digest = hash(blob);
    expect(digest.toString('hex')).toBe(
      'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
    );
  });
});

describe('signBlob', () => {
  const key = generateKeyPair();
  it('returns the signature of the blob', () => {
    const blob = Buffer.from('hello world');
    const signature = signBlob(blob, key.privateKey);

    expect(signature).toBeTruthy();
  });
});

describe('verifyBlob', () => {
  const key = generateKeyPair();
  const blob = Buffer.from('hello world');
  const signature = signBlob(blob, key.privateKey);

  describe('when the signature is valid', () => {
    it('returns true', () => {
      expect(verifyBlob(blob, key.publicKey, signature)).toBe(true);
    });
  });

  describe('when the signature is invalid', () => {
    it('returns false', () => {
      expect(verifyBlob(Buffer.from('foo'), key.publicKey, signature)).toBe(
        false
      );
    });
  });
});

describe('randomBytes', () => {
  it('returns a buffer of the specified length', () => {
    const buffer = randomBytes(10);
    expect(buffer.length).toBe(10);
  });
});
