import { generateKeyPair, hash, signBlob, verifyBlob } from './crypto';

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

    expect(digest).toBe(
      'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
    );
  });
});

describe('signBlob', () => {
  const key = generateKeyPair();
  it('returns the signature of the blob', () => {
    const blob = Buffer.from('hello world');
    const signature = signBlob(key.privateKey, blob);

    expect(signature).toBeTruthy();
  });
});

describe('verifyBlob', () => {
  const key = generateKeyPair();
  const blob = Buffer.from('hello world');

  describe('when the signature is valid', () => {
    const signature = signBlob(key.privateKey, blob);
    it('returns true', () => {
      expect(verifyBlob(key.publicKey, blob, signature)).toBe(true);
    });
  });

  describe('when the signature is invalid', () => {
    const signature = 'ABCXYZ';
    it('returns false', () => {
      expect(verifyBlob(key.publicKey, blob, signature)).toBe(false);
    });
  });
});
