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
import type { X509Certificate, crypto } from '@sigstore/core';

export type TLogAuthority = {
  logID: Buffer;
  publicKey: crypto.KeyObject;
  validFor: {
    start: Date;
    end: Date;
  };
};

export type CertAuthority = {
  certChain: X509Certificate[];
  validFor: {
    start: Date;
    end: Date;
  };
};

export type TimeConstrainedKey = {
  publicKey: crypto.KeyObject;
  validFor(date: Date): boolean;
};

export type KeyFinderFunc = (hint: string) => TimeConstrainedKey;

export type TrustMaterial = {
  certificateAuthorities: CertAuthority[];
  timestampAuthorities: CertAuthority[];
  tlogs: TLogAuthority[];
  ctlogs: TLogAuthority[];
  publicKey: KeyFinderFunc;
};
