import { verify } from '../crypto';
import { createPublicKey } from '../crypto';
import crypto from 'crypto';
import assert from 'assert';

// 1. Test base64 DER public key
test('base64 DER public key', () => {
  // Generate a real EC key pair
  const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const derBase64 = der.toString('base64');
  // Test patched createPublicKey
  const keyObj = createPublicKey(derBase64);
  assert(keyObj, 'createPublicKey should return a KeyObject for base64 DER');
  console.log('Base64 DER key parsed successfully');
});

// 2. verify() passes undefined algorithm for Ed25519
test('verify() passes undefined algorithm for Ed25519', () => {
  const data = Buffer.from('verify me');
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const sig = crypto.sign(null, data, keyPair.privateKey);

  const ok = verify(data, keyPair.publicKey, sig);
  assert(ok, 'verify() should work with Ed25519 without specifying a digest');
  console.log('verify() Ed25519 works');
});

