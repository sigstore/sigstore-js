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

// KeyMaterial is a union type representing either a public key or an X.509
// certificate.
export type KeyMaterial =
  | {
      $case: 'x509Certificate';
      certificate: string;
    }
  | {
      $case: 'publicKey';
      publicKey: string;
      hint?: string;
    };

// The Signature returned by a Signer. Includes the signature and the key
// material (either a public key or an X.509 certificate) which can be used to
// verify the signature.
export type Signature = {
  signature: Buffer;
  key: KeyMaterial;
};

// A Signer is responsible for generating a signature for the given blob
// of data. The signature is returned as an Signature, which also includes
// the key material used for verification.
export interface Signer {
  sign: (data: Buffer) => Promise<Signature>;
}
