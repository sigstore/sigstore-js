import { PolicyError } from './error';
import { CertificateExtensions } from './shared.types';

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
  signerExtensions: CertificateExtensions
): void {
  if (policyExtensions.issuer) {
    const policyIssuer = policyExtensions.issuer;
    const signerIssuer = signerExtensions.issuer;

    if (signerIssuer === undefined || signerIssuer !== policyIssuer) {
      throw new PolicyError({
        code: 'UNTRUSTED_SIGNER_ERROR',
        message: `invalid certificate issuer - expected ${policyIssuer}, got ${signerIssuer}`,
      });
    }
  }
}
