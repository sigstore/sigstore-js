import {
  CertificateAuthority,
  HashAlgorithm,
  PublicKeyDetails,
  TransparencyLogInstance,
} from '@sigstore/protobuf-specs';
import type { CA, CTLog } from './fulcio';
import type { TLog } from './rekor';

function trustCA(ca: CA): CertificateAuthority {
  return {
    subject: {
      commonName: 'sigstore',
      organization: 'sigstore.mock',
    },
    uri: 'https://fulcio.sigstore.dev',
    certChain: {
      certificates: [
        {
          rawBytes: ca.rootCertificate,
        },
      ],
    },
    validFor: {
      start: new Date(),
    },
  };
}

function trustTLog(tlog: TLog): TransparencyLogInstance {
  return {
    baseUrl: 'https://rekor.sigstore.dev',
    logId: { keyId: Buffer.from(tlog.logID) },
    hashAlgorithm: HashAlgorithm.SHA2_256,
    publicKey: {
      rawBytes: tlog.publicKey.export({ type: 'spki', format: 'der' }),
      keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
      validFor: {
        start: new Date(),
      },
    },
  };
}

function trustCTLog(ctlog: CTLog): TransparencyLogInstance {
  return {
    baseUrl: 'https://ctfe.sigstore.dev',
    logId: { keyId: ctlog.logID },
    hashAlgorithm: HashAlgorithm.SHA2_256,
    publicKey: {
      rawBytes: ctlog.publicKey,
      keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
      validFor: {
        start: new Date(),
      },
    },
  };
}
