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
import { bufferEqual, createPublicKey, digest, verify } from '../crypto';
import crypto, { generateKeyPairSync, sign } from 'crypto';

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

  it('should create a public key from a base64-encoded DER string', () => {
    const input =
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==';
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

describe('digest', () => {
  const expectedDigest =
    'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';

  it('returns the SHA256 digest of the blob', () => {
    const blob = Buffer.from('hello world');
    const d = digest('sha256', blob);
    expect(d.toString('hex')).toBe(expectedDigest);
  });

  it('returns the SHA256 digest of a string', () => {
    const d = digest('sha256', 'hello world');
    expect(d.toString('hex')).toBe(expectedDigest);
  });

  it('returns the SHA256 digest of an ArrayBuffer', () => {
    const view = new TextEncoder().encode('hello world');
    const blob = view.buffer.slice(
      view.byteOffset,
      view.byteOffset + view.byteLength
    );
    const d = digest('sha256', blob);
    expect(d.toString('hex')).toBe(expectedDigest);
  });
});

describe('verify', () => {
  const keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const data = Buffer.from('test data');
  const signature = sign('sha256', data, keyPair.privateKey);

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('returns true for a valid signature', () => {
    expect(verify(data, keyPair.publicKey, signature, 'sha256')).toBe(true);
  });

  it('returns false for an invalid signature', () => {
    const badSig = Buffer.from('bad signature');
    expect(verify(data, keyPair.publicKey, badSig, 'sha256')).toBe(false);
  });

  it('uses sha256 by default for EC keys', () => {
    const nodeVerify = jest.spyOn(crypto, 'verify');

    expect(verify(data, keyPair.publicKey, signature)).toBe(true);
    expect(nodeVerify).toHaveBeenCalledWith(
      'sha256',
      data,
      keyPair.publicKey,
      signature
    );
  });

  it('uses sha256 by default for PEM-encoded EC keys', () => {
    const nodeVerify = jest.spyOn(crypto, 'verify');
    const pem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });

    for (const key of [pem, Buffer.from(pem)]) {
      expect(verify(data, key, signature)).toBe(true);
      expect(nodeVerify).toHaveBeenLastCalledWith(
        'sha256',
        data,
        key,
        signature
      );
    }
  });

  it('uses sha256 by default for RSA keys', () => {
    const nodeVerify = jest.spyOn(crypto, 'verify');
    const rsaKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaSignature = sign('sha256', data, rsaKeyPair.privateKey);

    expect(verify(data, rsaKeyPair.publicKey, rsaSignature)).toBe(true);
    expect(nodeVerify).toHaveBeenCalledWith(
      'sha256',
      data,
      rsaKeyPair.publicKey,
      rsaSignature
    );
  });

  it('leaves the algorithm unspecified for Ed25519 keys', () => {
    const nodeVerify = jest.spyOn(crypto, 'verify');
    const ed25519KeyPair = generateKeyPairSync('ed25519');
    const ed25519Signature = sign(null, data, ed25519KeyPair.privateKey);

    expect(verify(data, ed25519KeyPair.publicKey, ed25519Signature)).toBe(true);
    expect(nodeVerify).toHaveBeenCalledWith(
      undefined,
      data,
      ed25519KeyPair.publicKey,
      ed25519Signature
    );
  });

  it('preserves the default digest for restricted RSA-PSS keys', () => {
    const nodeVerify = jest.spyOn(crypto, 'verify');
    const rsaPssKeyPair = generateKeyPairSync('rsa-pss', {
      modulusLength: 2048,
      hashAlgorithm: 'sha384',
      mgf1HashAlgorithm: 'sha384',
    });
    const rsaPssSignature = sign('sha384', data, rsaPssKeyPair.privateKey);
    const pem = rsaPssKeyPair.publicKey.export({ type: 'spki', format: 'pem' });

    for (const key of [rsaPssKeyPair.publicKey, pem]) {
      expect(verify(data, key, rsaPssSignature)).toBe(true);
      expect(nodeVerify).toHaveBeenLastCalledWith(
        undefined,
        data,
        key,
        rsaPssSignature
      );
    }
  });

  it('honors an explicitly supplied digest', () => {
    const nodeVerify = jest.spyOn(crypto, 'verify');
    const sha384Signature = sign('sha384', data, keyPair.privateKey);

    expect(verify(data, keyPair.publicKey, sha384Signature, 'sha384')).toBe(
      true
    );
    expect(nodeVerify).toHaveBeenCalledWith(
      'sha384',
      data,
      keyPair.publicKey,
      sha384Signature
    );
  });

  it('returns false for an invalid signature when the algorithm is omitted', () => {
    expect(verify(data, keyPair.publicKey, Buffer.from('bad signature'))).toBe(
      false
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
