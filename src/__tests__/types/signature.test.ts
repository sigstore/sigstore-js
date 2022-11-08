/*
Copyright 2022 The Sigstore Authors.

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
import { Envelope } from '../../types/bundle';
import { extractSignatureMaterial } from '../../types/signature';

describe('extractSignatureMaterial', () => {
  const envelope: Envelope = {
    payload: Buffer.from('Hello, world!'),
    payloadType: 'text/plain',
    signatures: [
      {
        keyid: 'keyid',
        sig: Buffer.from('signature'),
      },
    ],
  };

  const publicKey = '-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----';

  it('returns the correct signature material', () => {
    const sigMaterial = extractSignatureMaterial(envelope, publicKey);

    expect(sigMaterial.key).toBeDefined();
    expect(sigMaterial.signature).toEqual(envelope.signatures[0].sig);
    expect(sigMaterial.key?.id).toEqual(envelope.signatures[0].keyid);
    expect(sigMaterial.key?.value).toEqual(publicKey);
    expect(sigMaterial.certificates).toBeUndefined();
  });
});
