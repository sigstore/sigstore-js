import { PolicyError } from './error';
import { CertificateExtensions } from './shared.types';

// Verifies that the signer's SAN matches the policy identity. The
// policyIdentity is treated as a JavaScript regular expression pattern and
// tested against the full signerIdentity string. For exact matching, use
// anchored patterns (e.g. '^user@example\\.com$').
export function verifySubjectAlternativeName(
  policyIdentity: string,
  signerIdentity: string | undefined
): void {
  if (signerIdentity === undefined || !signerIdentity.match(policyIdentity)) {
    throw new PolicyError({
      code: 'UNTRUSTED_SIGNER_ERROR',
      message: `certificate identity error - expected ${policyIdentity}, got ${signerIdentity}`,
    });
  }
}

export function verifyExtensions(
  policyExtensions: CertificateExtensions,
  signerExtensions: CertificateExtensions = {}
): void {
  let key: keyof typeof policyExtensions;
  for (key in policyExtensions) {
    if (signerExtensions[key] !== policyExtensions[key]) {
      throw new PolicyError({
        code: 'UNTRUSTED_SIGNER_ERROR',
        message: `invalid certificate extension - expected ${key}=${policyExtensions[key]}, got ${key}=${signerExtensions[key]}`,
      });
    }
  }
}
