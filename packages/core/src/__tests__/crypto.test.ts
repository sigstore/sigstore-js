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
import { ED25519_D, isValidEd25519Point } from '../ed25519';
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

describe('Ed25519 public key validation', () => {
  const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
  const toSPKI = (hex: string): Buffer =>
    Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(hex, 'hex')]);

  // Every encoding of a point of order 1, 2, 4 or 8, including the
  // non-canonical (y >= p) aliases and x = 0 encodings with the sign bit set.
  const smallOrderEncodings: Record<string, string> = {
    'order 1 (identity)':
      '0100000000000000000000000000000000000000000000000000000000000000',
    'order 1, sign bit set':
      '0100000000000000000000000000000000000000000000000000000000000080',
    'order 2':
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'order 2, sign bit set':
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'order 4':
      '0000000000000000000000000000000000000000000000000000000000000000',
    'order 4, sign bit set':
      '0000000000000000000000000000000000000000000000000000000000000080',
    'order 8 (a)':
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'order 8 (a), sign bit set':
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    'order 8 (b)':
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'order 8 (b), sign bit set':
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    'non-canonical y = p (order 4)':
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'non-canonical y = p (order 4), sign bit set':
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    'non-canonical y = p + 1 (identity)':
      'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'non-canonical y = p + 1 (identity), sign bit set':
      'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  };

  // RFC 8032, section 7.1 test vectors.
  const rfc8032Keys: Record<string, string> = {
    'TEST 1':
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    'TEST 2':
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    'TEST 3':
      'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    'TEST 1024':
      '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
    'TEST SHA(abc)':
      'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
  };

  // R = identity, S = 0.
  const identitySignature = Buffer.from(
    '01' + '00'.repeat(31) + '00'.repeat(32),
    'hex'
  );

  it('uses the RFC 8032 curve constant d', () => {
    expect(ED25519_D).toBe(
      BigInt(
        '37095705934669439343138083508754565189542113879843219016388785533085940283555'
      )
    );
  });

  it('covers 14 distinct small-order encodings', () => {
    expect(new Set(Object.values(smallOrderEncodings)).size).toBe(14);
  });

  describe.each(Object.entries(smallOrderEncodings))(
    'small-order key: %s',
    (_, hex) => {
      it('is rejected as a point', () => {
        expect(isValidEd25519Point(Buffer.from(hex, 'hex'))).toBe(false);
      });

      it('is rejected by createPublicKey', () => {
        expect(() => createPublicKey(toSPKI(hex))).toThrow(
          /invalid Ed25519 public key/
        );
      });

      it('is rejected by verify when given as a KeyObject', () => {
        const key = crypto.createPublicKey({
          key: toSPKI(hex),
          format: 'der',
          type: 'spki',
        });
        expect(verify(Buffer.from('message'), key, identitySignature)).toBe(
          false
        );
      });
    }
  );

  it('rejects a non-canonical y >= p that is not small-order', () => {
    // y = p + 3, which reduces to the on-curve y = 3.
    const hex =
      'f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f';
    expect(isValidEd25519Point(Buffer.from(hex, 'hex'))).toBe(false);
    expect(
      isValidEd25519Point(
        Buffer.from(
          '0300000000000000000000000000000000000000000000000000000000000000',
          'hex'
        )
      )
    ).toBe(true);
  });

  it('rejects the maximum 255-bit y', () => {
    expect(isValidEd25519Point(Buffer.alloc(32, 0xff))).toBe(false);
  });

  it('rejects an off-curve point', () => {
    // y = 2 has no corresponding x on edwards25519.
    const hex =
      '0200000000000000000000000000000000000000000000000000000000000000';
    expect(isValidEd25519Point(Buffer.from(hex, 'hex'))).toBe(false);
    expect(() => createPublicKey(toSPKI(hex))).toThrow();
  });

  it('rejects encodings of the wrong length', () => {
    expect(isValidEd25519Point(Buffer.alloc(31))).toBe(false);
    expect(isValidEd25519Point(Buffer.alloc(33))).toBe(false);
  });

  describe.each(Object.entries(rfc8032Keys))('RFC 8032 key %s', (_, hex) => {
    it('is accepted', () => {
      expect(isValidEd25519Point(Buffer.from(hex, 'hex'))).toBe(true);
      expect(createPublicKey(toSPKI(hex)).asymmetricKeyType).toBe('ed25519');
    });
  });

  it('verifies the RFC 8032 TEST 1 signature', () => {
    const key = createPublicKey(toSPKI(rfc8032Keys['TEST 1']));
    const sig = Buffer.from(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
      'hex'
    );
    expect(verify(Buffer.alloc(0), key, sig)).toBe(true);
    expect(verify(Buffer.from('x'), key, sig)).toBe(false);
  });

  it('accepts generated keys in every supported input form', () => {
    for (let i = 0; i < 32; i++) {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const der = publicKey.export({ format: 'der', type: 'spki' });
      const pem = publicKey.export({ format: 'pem', type: 'spki' }) as string;
      const data = Buffer.from(`message ${i}`);
      const sig = sign(null, data, privateKey);

      for (const input of [der, der.toString('base64'), pem]) {
        const key = createPublicKey(input);
        expect(verify(data, key, sig)).toBe(true);
        expect(verify(Buffer.from('tampered'), key, sig)).toBe(false);
      }
      expect(verify(data, pem, sig)).toBe(true);
    }
  });

  it('identity point key is rejected', () => {
    const keyObject = crypto.createPublicKey({
      key: toSPKI(smallOrderEncodings['order 1 (identity)']),
      format: 'der',
      type: 'spki',
    });
    const pem = keyObject.export({ format: 'pem', type: 'spki' });

    for (const msg of ['hello', 'another payload', 'x'.repeat(1000)]) {
      expect(verify(Buffer.from(msg), keyObject, identitySignature)).toBe(
        false
      );
      expect(verify(Buffer.from(msg), pem, identitySignature)).toBe(false);
    }
  });

  it('does not affect EC or RSA keys', () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const data = Buffer.from('data');

    for (const kp of [ec, rsa]) {
      const der = kp.publicKey.export({ format: 'der', type: 'spki' });
      const key = createPublicKey(der);
      expect(verify(data, key, sign('sha256', data, kp.privateKey))).toBe(true);
    }
  });
});
