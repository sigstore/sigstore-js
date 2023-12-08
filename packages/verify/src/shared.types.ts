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
import type { TransparencyLogEntry } from '@sigstore/bundle';
import type { X509Certificate, crypto } from '@sigstore/core';

export type CertificateExtensionName = 'issuer';
export type CertificateExtensions = {
  [key in CertificateExtensionName]?: string;
};

export type CertificateIdentity = {
  subjectAlternativeName?: string;
  extensions?: CertificateExtensions;
};

export type VerificationPolicy = CertificateIdentity;

export type Signer = {
  key: crypto.KeyObject;
  identity?: CertificateIdentity;
};

// TODO: Implement this!
export type RFC3161Timestamp = object;

export type Timestamp =
  | {
      $case: 'timestamp-authority';
      timestamp: RFC3161Timestamp;
    }
  | {
      $case: 'transparency-log';
      tlogEntry: TransparencyLogEntry;
    };

export type VerificationKey =
  | {
      $case: 'public-key';
      hint: string;
    }
  | {
      $case: 'certificate';
      certificate: X509Certificate;
    };

export type SignatureContent = {
  compareSignature(signature: Buffer): boolean;
  compareDigest(digest: Buffer): boolean;
  verifySignature(key: crypto.KeyObject): boolean;
};

export type TimestampProvider = {
  timestamps: Timestamp[];
};

export type SignatureProvider = {
  signature: SignatureContent;
};

export type KeyProvider = {
  key: VerificationKey;
};

export type TLogEntryProvider = {
  tlogEntries: TransparencyLogEntry[];
};

export type SignedEntity = SignatureProvider &
  KeyProvider &
  TimestampProvider &
  TLogEntryProvider;
