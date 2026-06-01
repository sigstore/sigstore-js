import { PolicyError } from './error';
import { CertificateExtensions } from './shared.types';

import type { ObjectIdentifierValuePair } from '@sigstore/protobuf-specs';

// Verifies that the signer's SAN matches the policy identity. The
// policyIdentity is treated as a JavaScript regular expression pattern and
// tested against the full signerIdentity string. For exact matching, use
// anchored patterns (e.g. '^user@example\\.com$').
export function verifySubjectAlternativeName(
  policyIdentity: string | RegExp,
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

export function verifyOIDs(
  policyOIDs: ObjectIdentifierValuePair[],
  signerOIDs: ObjectIdentifierValuePair[] = []
): void {
  for (const policyOID of policyOIDs) {
    const match = signerOIDs.find(
      (signerOID) =>
        oidEquals(policyOID.oid?.id, signerOID.oid?.id) &&
        policyOID.value.equals(signerOID.value)
    );

    if (!match) {
      /* istanbul ignore next */
      const oid = policyOID.oid?.id.join('.') ?? '<unknown>';
      throw new PolicyError({
        code: 'UNTRUSTED_SIGNER_ERROR',
        message: `invalid certificate extension - missing OID ${oid}`,
      });
    }
  }
}

function oidEquals(a: number[] | undefined, b: number[] | undefined): boolean {
  /* istanbul ignore if */
  if (a === undefined || b === undefined) {
    return false;
  }
  return a.length === b.length && a.every((v, i) => v === b[i]);
}
