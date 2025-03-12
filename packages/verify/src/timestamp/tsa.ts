import { RFC3161Timestamp, crypto } from '@sigstore/core';
import { VerificationError } from '../error';
import { CertificateChainVerifier } from '../key/certificate';
import { CertAuthority, filterCertAuthorities } from '../trust';

export function verifyRFC3161Timestamp(
  timestamp: RFC3161Timestamp,
  data: Buffer,
  timestampAuthorities: CertAuthority[]
): void {
  const signingTime = timestamp.signingTime;

  // Filter for CAs which were valid at the time of signing
  timestampAuthorities = filterCertAuthorities(
    timestampAuthorities,
    signingTime
  );

  // Filter for CAs which match serial and issuer embedded in the timestamp
  timestampAuthorities = filterCAsBySerialAndIssuer(timestampAuthorities, {
    serialNumber: timestamp.signerSerialNumber,
    issuer: timestamp.signerIssuer,
  });

  // Check that we can verify the timestamp with AT LEAST ONE of the remaining
  // CAs
  const verified = timestampAuthorities.some((ca) => {
    try {
      verifyTimestampForCA(timestamp, data, ca);
      return true;
    } catch (e) {
      return false;
    }
  });

  if (!verified) {
    throw new VerificationError({
      code: 'TIMESTAMP_ERROR',
      message: 'timestamp could not be verified',
    });
  }
}

function verifyTimestampForCA(
  timestamp: RFC3161Timestamp,
  data: Buffer,
  ca: CertAuthority
): void {
  const [leaf, ...cas] = ca.certChain;
  const signingKey = crypto.createPublicKey(leaf.publicKey);
  const signingTime = timestamp.signingTime;

  // Verify the certificate chain for the provided CA
  try {
    new CertificateChainVerifier({
      untrustedCert: leaf,
      trustedCerts: cas,
      timestamp: signingTime,
    }).verify();
  } catch (e) {
    throw new VerificationError({
      code: 'TIMESTAMP_ERROR',
      message: 'invalid certificate chain',
    });
  }

  // Check that the signing certificate's key can be used to verify the
  // timestamp signature.
  timestamp.verify(data, signingKey);
}

// Filters the list of CAs to those which have a leaf signing certificate which
// matches the given serial number and issuer.
function filterCAsBySerialAndIssuer(
  timestampAuthorities: CertAuthority[],
  criteria: { serialNumber: Buffer; issuer: Buffer }
): CertAuthority[] {
  return timestampAuthorities.filter(
    (ca) =>
      ca.certChain.length > 0 &&
      crypto.bufferEqual(ca.certChain[0].serialNumber, criteria.serialNumber) &&
      crypto.bufferEqual(ca.certChain[0].issuer, criteria.issuer)
  );
}
