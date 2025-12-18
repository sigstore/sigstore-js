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
import { X509Certificate, crypto } from '@sigstore/core';
import {
  PublicKeyDetails,
  type CertificateAuthority,
  type PublicKey,
  type TransparencyLogInstance,
  type TrustedRoot,
} from '@sigstore/protobuf-specs';
import { VerificationError } from '../error';
import type {
  CertAuthority,
  KeyFinderFunc,
  TLogAuthority,
  TrustMaterial,
} from './trust.types';

const BEGINNING_OF_TIME = new Date(0);
const END_OF_TIME = new Date(8640000000000000);

export { filterCertAuthorities, filterTLogAuthorities } from './filter';

export type {
  CertAuthority,
  KeyFinderFunc,
  TLogAuthority,
  TrustMaterial,
} from './trust.types';

export function toTrustMaterial(
  root: TrustedRoot,
  keys?: Record<string, PublicKey> | KeyFinderFunc
): TrustMaterial {
  const keyFinder = typeof keys === 'function' ? keys : keyLocator(keys);

  return {
    certificateAuthorities:
      root.certificateAuthorities.map(createCertAuthority),
    timestampAuthorities: root.timestampAuthorities.map(createCertAuthority),
    tlogs: root.tlogs.map(createTLogAuthority),
    ctlogs: root.ctlogs.map(createTLogAuthority),
    publicKey: keyFinder,
  };
}

function createTLogAuthority(
  tlogInstance: TransparencyLogInstance
): TLogAuthority {
  const keyDetails = tlogInstance.publicKey!.keyDetails;
  const keyType =
    keyDetails === PublicKeyDetails.PKCS1_RSA_PKCS1V5 ||
    keyDetails === PublicKeyDetails.PKIX_RSA_PKCS1V5 ||
    keyDetails === PublicKeyDetails.PKIX_RSA_PKCS1V15_2048_SHA256 ||
    keyDetails === PublicKeyDetails.PKIX_RSA_PKCS1V15_3072_SHA256 ||
    keyDetails === PublicKeyDetails.PKIX_RSA_PKCS1V15_4096_SHA256
      ? 'pkcs1'
      : 'spki';
  /* istanbul ignore next */
  return {
    baseURL: tlogInstance.baseUrl,
    logID: tlogInstance.checkpointKeyId
      ? tlogInstance.checkpointKeyId.keyId
      : tlogInstance.logId!.keyId,
    publicKey: crypto.createPublicKey(
      tlogInstance.publicKey!.rawBytes!,
      keyType
    ),
    validFor: {
      start: tlogInstance.publicKey!.validFor?.start || BEGINNING_OF_TIME,
      end: tlogInstance.publicKey!.validFor?.end || END_OF_TIME,
    },
  };
}

function createCertAuthority(ca: CertificateAuthority): CertAuthority {
  /* istanbul ignore next */
  return {
    certChain: ca.certChain!.certificates.map((cert) => {
      return X509Certificate.parse(Buffer.from(cert.rawBytes));
    }),
    validFor: {
      start: ca.validFor?.start || BEGINNING_OF_TIME,
      end: ca.validFor?.end || END_OF_TIME,
    },
  };
}

function keyLocator(keys?: Record<string, PublicKey>): KeyFinderFunc {
  return (hint: string) => {
    const key = (keys || {})[hint];

    if (!key) {
      throw new VerificationError({
        code: 'PUBLIC_KEY_ERROR',
        message: `key not found: ${hint}`,
      });
    }

    return {
      publicKey: crypto.createPublicKey(key.rawBytes!),
      validFor: (date: Date) => {
        /* istanbul ignore next */
        return (
          (key.validFor?.start || BEGINNING_OF_TIME) <= date &&
          (key.validFor?.end || END_OF_TIME) >= date
        );
      },
    };
  };
}
