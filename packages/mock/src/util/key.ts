import { Crypto, CryptoKey } from '@peculiar/webcrypto';
import crypto from 'crypto';

export function generateKeyPair(
  namedCurve: string = 'P-256'
): crypto.KeyPairKeyObjectResult {
  return crypto.generateKeyPairSync('ec', { namedCurve });
}

// Translates a Node.js KeyObject to a WebCrypto CryptoKey
export async function keyObjectToCryptoKey(
  keyObject: crypto.KeyObject
): Promise<CryptoKey> {
  const keyData = keyObject.export({ format: 'jwk' });
  const algorithm = { name: 'ECDSA', namedCurve: namedCurve(keyObject) };
  const extractable = true;
  const usages: KeyUsage[] =
    keyObject.type === 'private' ? ['sign'] : ['verify'];

  return await new Crypto().subtle.importKey(
    'jwk',
    keyData,
    algorithm,
    extractable,
    usages
  );
}

function namedCurve(key: crypto.KeyObject): string {
  /* istanbul ignore next */
  switch (key.asymmetricKeyDetails?.namedCurve) {
    case 'prime256v1':
      return 'P-256';
    case 'secp384r1':
      return 'P-384';
    case 'secp521r1':
      return 'P-521';
    default:
      /* istanbul ignore next */
      throw new Error(
        `Unsupported curve ${key.asymmetricKeyDetails?.namedCurve}`
      );
  }
}
