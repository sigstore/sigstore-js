import { verify } from '../crypto';
import { createPublicKey } from '../crypto';
import crypto from 'crypto';
import assert from 'assert';
import { test } from 'bun:test';

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

// 2. Test verify() default SHA-256
test('verify() defaults to SHA-256', () => {
	const data = Buffer.from('verify me');
	const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
	const sig = crypto.sign('sha256', data, keyPair.privateKey);
	// verify from core/src/crypto defaults to sha256 if algorithm is undefined
	const ok = verify(data, keyPair.publicKey, sig);
	assert(ok, 'verify() should default to sha256');
	console.log('verify() default SHA-256 works');
});
