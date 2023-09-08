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
export const DIGEST_SHA256 = 'SHA-256';

export const KEY_ALGORITHM_ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' };

export const SIGNING_ALGORITHM_ECDSA_SHA256 = {
  name: 'ECDSA',
  hash: 'SHA-256',
};
export const SIGNING_ALGORITHM_ECDSA_SHA384 = {
  name: 'ECDSA',
  hash: 'SHA-384',
};
