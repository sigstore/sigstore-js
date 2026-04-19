import { createSign } from 'crypto';
import type { Signature, Signer } from '@sigstore/sign';

// PEM-encoded EC P-256 private key used for all signing operations
const STATIC_PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP6oF4PdxGz4bbyOutAK/WjB1/eH7UFepKxsSU1TB7SRoAoGCCqGSM49
AwEHoUQDQgAErXB5IxdtJRuhULkZxdAKUZiqX3GpEm3wRxhQf3cw9pq3C3KM9gDy
VOwEHD00iIxLMrLxXPzFOgu1e6q9Up7ssg==
-----END EC PRIVATE KEY-----`;

// PEM-encoded public key corresponding to the static private key above
const STATIC_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErXB5IxdtJRuhULkZxdAKUZiqX3Gp
Em3wRxhQf3cw9pq3C3KM9gDyVOwEHD00iIxLMrLxXPzFOgu1e6q9Up7ssg==
-----END PUBLIC KEY-----`;

// Signer implementation which uses a fixed, hard-coded EC key pair for all
// signing operations. Unlike EphemeralSigner, the key material is constant
// across invocations.
export class StaticSigner implements Signer {
  public async sign(data: Buffer): Promise<Signature> {
    const signer = createSign('sha256');
    signer.update(data);
    signer.end();

    const signature = signer.sign(STATIC_PRIVATE_KEY);

    return {
      signature,
      key: { $case: 'publicKey', publicKey: STATIC_PUBLIC_KEY },
    };
  }
}
