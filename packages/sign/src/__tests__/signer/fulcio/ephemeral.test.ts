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
import assert from 'assert';
import { EphemeralSigner } from '../../../signer/fulcio/ephemeral';

describe('EphemeralSigner', () => {
  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new EphemeralSigner();
      expect(client).toBeDefined();
    });
  });

  describe('sign', () => {
    const subject = new EphemeralSigner();
    const message = Buffer.from('message');

    it('returns the signature', async () => {
      const signature = await subject.sign(message);
      expect(signature).toBeDefined();
      expect(signature.signature).toBeDefined();
      expect(signature.key.$case).toEqual('publicKey');
      assert(signature.key.$case === 'publicKey');
      expect(signature.key.publicKey).toBeDefined();
    });
  });
});
