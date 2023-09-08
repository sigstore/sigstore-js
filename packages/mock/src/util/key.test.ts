import { generateKeyPair, keyObjectToCryptoKey } from './key';

describe('keyObjectToCryptoKey', () => {
  describe('with a P-256 key', () => {
    const key = generateKeyPair();
    it('converts a private key', async () => {
      const ck = await keyObjectToCryptoKey(key.privateKey);
      expect(ck).toBeDefined();
      expect(ck.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-256' });
      expect(ck.type).toEqual('private');
    });

    it('converts a public key', async () => {
      const ck = await keyObjectToCryptoKey(key.publicKey);
      expect(ck).toBeDefined();
      expect(ck.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-256' });
      expect(ck.type).toEqual('public');
    });
  });

  describe('with a P-384 key', () => {
    const key = generateKeyPair('secp384r1');
    it('converts a private key', async () => {
      const ck = await keyObjectToCryptoKey(key.privateKey);
      expect(ck).toBeDefined();
      expect(ck.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-384' });
      expect(ck.type).toEqual('private');
    });

    it('converts a public key', async () => {
      const ck = await keyObjectToCryptoKey(key.publicKey);
      expect(ck).toBeDefined();
      expect(ck.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-384' });
      expect(ck.type).toEqual('public');
    });
  });

  describe('with a P-521 key', () => {
    const key = generateKeyPair('secp521r1');
    it('converts a private key', async () => {
      const ck = await keyObjectToCryptoKey(key.privateKey);
      expect(ck).toBeDefined();
      expect(ck.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-521' });
      expect(ck.type).toEqual('private');
    });

    it('converts a public key', async () => {
      const ck = await keyObjectToCryptoKey(key.publicKey);
      expect(ck).toBeDefined();
      expect(ck.algorithm).toEqual({ name: 'ECDSA', namedCurve: 'P-521' });
      expect(ck.type).toEqual('public');
    });
  });
});
