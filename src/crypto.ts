import {
  createSign,
  createVerify,
  createHash,
  generateKeyPairSync,
  randomBytes as randBytes,
  KeyPairKeyObjectResult,
  KeyLike,
  BinaryLike,
  BinaryToTextEncoding,
} from 'crypto';

const EC_KEYPAIR_TYPE = 'ec';
const P256_CURVE = 'P-256';
const SHA256_ALGORITHM = 'sha256';
const BASE64_ENCODING = 'base64';

export function generateKeyPair(): KeyPairKeyObjectResult {
  return generateKeyPairSync(EC_KEYPAIR_TYPE, { namedCurve: P256_CURVE });
}

export function signBlob(privateKey: KeyLike, blob: BinaryLike): string {
  const signer = createSign(SHA256_ALGORITHM);
  signer.update(blob);
  signer.end();
  return signer.sign(privateKey, BASE64_ENCODING);
}

export function verifyBlob(
  publicKey: KeyLike,
  blob: BinaryLike,
  signature: string
): boolean {
  const verifier = createVerify(SHA256_ALGORITHM);
  verifier.update(blob);
  verifier.end();
  return verifier.verify(publicKey, signature, BASE64_ENCODING);
}

export function hash(
  blob: BinaryLike,
  encoding: BinaryToTextEncoding = 'hex'
): string {
  const hash = createHash(SHA256_ALGORITHM);
  hash.update(blob);
  return hash.digest(encoding);
}

export async function randomBytes(count: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    randBytes(count, (err, buf) => {
      if (err) {
        reject(err);
      } else {
        resolve(buf);
      }
    });
  });
}
