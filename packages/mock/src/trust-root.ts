/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import {
  CertificateAuthority,
  HashAlgorithm,
  PublicKeyDetails,
  TransparencyLogInstance,
} from '@sigstore/protobuf-specs';
import crypto from 'crypto';
import type { CA, CTLog } from './fulcio';
import type { TLog } from './rekor';

/* eslint-disable-next-line @typescript-eslint/no-unused-vars */
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

/* eslint-disable-next-line @typescript-eslint/no-unused-vars */
function trustTLog(tlog: TLog): TransparencyLogInstance {
  return {
    baseUrl: 'https://rekor.sigstore.dev',
    logId: {
      keyId: crypto.createHash('sha256').update(tlog.publicKey).digest(),
    },
    hashAlgorithm: HashAlgorithm.SHA2_256,
    publicKey: {
      rawBytes: tlog.publicKey,
      keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
      validFor: {
        start: new Date(),
      },
    },
  };
}

/* eslint-disable-next-line @typescript-eslint/no-unused-vars */
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
