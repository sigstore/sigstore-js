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
import { KeyObject, generateKeyPairSync, sign } from 'crypto';
import {
  bufferEqual,
  createPublicKey,
  hash,
  randomBytes,
  verifyBlob,
} from '../../util/crypto';

describe('createPublicKey', () => {
  describe('when the input in a PEM-encoded key', () => {
    const pem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtZO/hiYFB3WveI+iYoN4I6w17rSA
tbn02XdfIl+ZhQqUZv88dgDB86bfKyoOokA7fagAEOulkquhKKoOxdOySQ==
-----END PUBLIC KEY-----`;

    it('creates a public key', () => {
      const key = createPublicKey(pem);
      expect(key).toBeDefined();
      expect((key as KeyObject).asymmetricKeyType).toBe('ec');
    });
  });

  describe('when the input is a DER-encoded key', () => {
    const der = Buffer.from(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtZO/hiYFB3WveI+iYoN4I6w17rSAtbn02XdfIl+ZhQqUZv88dgDB86bfKyoOokA7fagAEOulkquhKKoOxdOySQ==',
      'base64'
    );

    it('creates a public key', () => {
      const key = createPublicKey(der);
      expect(key).toBeDefined();
      expect((key as KeyObject).asymmetricKeyType).toBe('ec');
    });
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

describe('verifyBlob', () => {
  const key = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const blob = Buffer.from('hello world');
  const signature = sign(null, blob, key.privateKey);

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

describe('bufferEqual', () => {
  it('returns true when the buffers are equal', () => {
    const buffer1 = Buffer.from('hello world');
    const buffer2 = Buffer.from('hello world');
    expect(bufferEqual(buffer1, buffer2)).toBe(true);
  });

  it('returns false when the buffers are not equal', () => {
    const buffer1 = Buffer.from('hello world');
    const buffer2 = Buffer.from('hello world!');
    expect(bufferEqual(buffer1, buffer2)).toBe(false);
  });
});
