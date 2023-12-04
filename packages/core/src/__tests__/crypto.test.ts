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
import { bufferEqual, createPublicKey, hash } from '../crypto';

describe('createPublicKey', () => {
  it('should create a public key from a PEM string', () => {
    const input = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFw
rkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`;
    const key = createPublicKey(input);
    expect(key).toBeDefined();
    expect(key.asymmetricKeyType).toBe('ec');
    expect(key.asymmetricKeyDetails).toEqual({ namedCurve: 'prime256v1' });
  });

  it('should create a public key from a DER buffer', () => {
    const input = Buffer.from(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
      'base64'
    );
    const key = createPublicKey(input);
    expect(key).toBeDefined();
    expect(key.asymmetricKeyType).toBe('ec');
    expect(key.asymmetricKeyDetails).toEqual({ namedCurve: 'prime256v1' });
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

describe('bufferEqual', () => {
  it('returns true when the buffers are equal', () => {
    const a = Buffer.from('hello world');
    const b = Buffer.from('hello world');
    expect(bufferEqual(a, b)).toBe(true);
  });

  it('returns false when the buffers are not equal', () => {
    const a = Buffer.from('hello world');
    const b = Buffer.from('hello world!');
    expect(bufferEqual(a, b)).toBe(false);
  });
});
