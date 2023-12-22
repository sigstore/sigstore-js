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
import * as core from '..';

it('exports classes', () => {
  expect(core.ASN1Obj).toBeInstanceOf(Function);
  expect(core.ByteStream).toBeInstanceOf(Function);
  expect(core.RFC3161Timestamp).toBeInstanceOf(Function);
  expect(core.X509Certificate).toBeInstanceOf(Function);
  expect(core.X509SCTExtension).toBeInstanceOf(Function);
});

it('exports modules', () => {
  expect(core.crypto).toBeDefined();
  expect(core.dsse).toBeDefined();
  expect(core.encoding).toBeDefined();
  expect(core.json).toBeDefined();
  expect(core.pem).toBeDefined();
});

it('exports constants', () => {
  expect(core.EXTENSION_OID_SCT).toBeDefined();
});
