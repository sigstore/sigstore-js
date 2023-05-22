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
import { SignatureError } from '../../error';
import { Artifact, createNotary } from '../../notary';
import { DSSENotary } from '../../notary/dsse';
import { MessageNotary } from '../../notary/message';

import type { SignatureMaterial, SignerFunc } from '../../types/signature';

describe('createNotary', () => {
  const artifact: Artifact = {
    data: Buffer.from('data'),
    type: 'text/plain',
  };

  const sigMaterial: SignatureMaterial = {
    signature: Buffer.from('signature'),
    certificates: undefined,
    key: { value: 'key', id: 'hint' },
  };

  const signer = jest.fn().mockResolvedValue(sigMaterial) satisfies SignerFunc;

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('when no signatory options are provided', () => {
    it('throws an error', () => {
      expect(() =>
        createNotary({ bundleType: 'dsseEnvelope' })
      ).toThrowWithCode(SignatureError, 'NO_SIGNATORY_ERROR');
    });
  });

  describe('when bundle type is "messageSignature"', () => {
    it('returns a message notary', () => {
      const notary = createNotary({
        bundleType: 'messageSignature',
        signer,
        rekorBaseURL: 'https://rekor.dev',
        tsaBaseURL: 'https://tsa.dev',
      });

      expect(notary).toBeInstanceOf(MessageNotary);
    });
  });

  describe('when bundle type is "dsseEnvelope"', () => {
    it('returns a DSSE notary', () => {
      const notary = createNotary({
        bundleType: 'dsseEnvelope',
        signer,
        rekorBaseURL: 'https://rekor.dev',
        tsaBaseURL: 'https://tsa.dev',
      });

      expect(notary).toBeInstanceOf(DSSENotary);
    });
  });

  describe('when configured with a signer', () => {
    it('returns a notary which invokes the configured signer', async () => {
      const notary = createNotary({ bundleType: 'messageSignature', signer });
      const b = await notary.notarize(artifact);

      expect(signer).toHaveBeenCalledWith(artifact.data);
    });

    it('returns a notary which unpacks the signers signature material properly', async () => {
      const notary = createNotary({ bundleType: 'messageSignature', signer });
      const b = await notary.notarize(artifact);

      assert(b.content.$case === 'messageSignature');
      expect(b.content.messageSignature.signature).toEqual(
        sigMaterial.signature
      );

      assert(b.verificationMaterial.content?.$case === 'publicKey');
      expect(b.verificationMaterial.content?.publicKey.hint).toEqual(
        sigMaterial.key.id
      );
    });
  });

  describe('when configured for keyless signing', () => {
    const idp = {
      getToken: jest.fn().mockResolvedValue('jwt'),
    };

    const fulcioBaseURL = 'http://localhost:8080';

    it('returns a notary', () => {
      const notary = createNotary({
        bundleType: 'messageSignature',
        fulcioBaseURL,
        identityProvider: idp,
      });

      expect(notary).toBeInstanceOf(MessageNotary);
    });
  });
});
