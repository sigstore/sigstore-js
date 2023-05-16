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
import { CallbackSigner, SignerFunc } from '../../signatory/callback';

import assert from 'assert';
import { SignatureError } from '../../error';
import type { SignatureMaterial } from '../../types/signature';

describe('CallbackSigner', () => {
  const data = Buffer.from('artifact');

  const signer = jest.fn();

  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new CallbackSigner({ signer });
      expect(client).toBeDefined();
    });
  });

  describe('sign', () => {
    describe('when the callback returns valid data', () => {
      const sigMaterial: SignatureMaterial = {
        signature: Buffer.from('signature'),
        certificates: undefined,
        key: { value: 'key', id: 'hint' },
      };

      const signer = jest
        .fn()
        .mockResolvedValue(sigMaterial) satisfies SignerFunc;

      const subject = new CallbackSigner({ signer });

      it('invokes the callback', async () => {
        await subject.sign(data);

        expect(signer).toHaveBeenCalledTimes(1);
        expect(signer).toHaveBeenCalledWith(data);
      });

      it('returns a signature', async () => {
        const endorsement = await subject.sign(data);

        expect(endorsement).toBeTruthy();
        expect(endorsement.signature).toEqual(sigMaterial.signature);
        expect(endorsement.key).toBeTruthy();
        assert(endorsement.key.$case === 'publicKey');
        expect(endorsement.key.publicKey).toEqual(sigMaterial.key.value);
        expect(endorsement.key.hint).toEqual(sigMaterial.key.id);
      });
    });

    describe('when the callback returns data with a missing signature', () => {
      const sigMaterial = {
        certificates: undefined,
        key: { value: 'key', id: 'hint' },
      };

      const signer = jest
        .fn()
        .mockResolvedValue(sigMaterial) satisfies SignerFunc;

      const subject = new CallbackSigner({ signer });

      it('returns a signature', async () => {
        await expect(subject.sign(data)).rejects.toThrowWithCode(
          SignatureError,
          'MISSING_SIGNATURE_ERROR'
        );
      });
    });

    describe('when the callback returns data with a missing key', () => {
      const sigMaterial = {
        signature: Buffer.from('signature'),
        certificates: undefined,
      };

      const signer = jest
        .fn()
        .mockResolvedValue(sigMaterial) satisfies SignerFunc;

      const subject = new CallbackSigner({ signer });

      it('returns a signature', async () => {
        await expect(subject.sign(data)).rejects.toThrowWithCode(
          SignatureError,
          'MISSING_PUBLIC_KEY_ERROR'
        );
      });
    });
  });
});
