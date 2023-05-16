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
import { MessageNotary } from '../../notary/message';
import * as sigstore from '../../types/sigstore';
import { crypto } from '../../util';

import type { Artifact } from '../../notary';
import type { Endorsement, Signatory } from '../../signatory';

describe('MessageNotary', () => {
  // Endorsement fixture to return from fake Signatory
  const signature = Buffer.from('signature');
  const key = 'publickey';

  const endorsement = {
    key: {
      $case: 'publicKey',
      publicKey: key,
      hint: 'hint',
    },
    signature: signature,
  } satisfies Endorsement;

  const signatory = {
    sign: jest.fn().mockResolvedValue(endorsement),
  } satisfies Signatory;

  describe('constructor', () => {
    it('should create a new instance', () => {
      const notary = new MessageNotary({ signatory, witnesses: [] });
      expect(notary).toBeDefined();
    });
  });

  describe('notarize', () => {
    const artifact: Artifact = {
      data: Buffer.from('artifact'),
    };

    const subject = new MessageNotary({ signatory, witnesses: [] });

    it('invokes the signatory', async () => {
      await subject.notarize(artifact);
      expect(signatory.sign).toHaveBeenCalled();
    });

    it('returns a bundle', async () => {
      const b = await subject.notarize(artifact);

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );

      assert(b.content?.$case === 'messageSignature');
      expect(b.content.messageSignature).toBeTruthy();
      expect(b.content.messageSignature.messageDigest.algorithm).toEqual(
        sigstore.HashAlgorithm.SHA2_256
      );
      expect(b.content.messageSignature.messageDigest.digest).toEqual(
        crypto.hash(artifact.data)
      );
      expect(b.content.messageSignature.signature).toEqual(signature);

      expect(b.verificationMaterial).toBeTruthy();
      assert(b.verificationMaterial.content?.$case === 'publicKey');
      expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
      expect(b.verificationMaterial.content?.publicKey.hint).toEqual(
        endorsement.key.hint
      );
    });
  });
});
