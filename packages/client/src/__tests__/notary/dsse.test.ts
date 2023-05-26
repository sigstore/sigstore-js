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
import { DSSENotary } from '../../notary/dsse';
import { dsse } from '../../util';

import type { Artifact } from '../../notary';
import type { Endorsement, Signatory } from '../../signatory';

describe('DSSENotary', () => {
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
      const notary = new DSSENotary({ signatory, witnesses: [] });
      expect(notary).toBeDefined();
    });
  });

  describe('notarize', () => {
    const subject = new DSSENotary({ signatory, witnesses: [] });

    describe('when the artifact type is NOT provided', () => {
      const artifact: Artifact = {
        data: Buffer.from('artifact'),
      };

      it('invokes the signatory', async () => {
        await subject.notarize(artifact);

        const expectedBlob = dsse.preAuthEncoding('', artifact.data);
        expect(signatory.sign).toHaveBeenCalledWith(expectedBlob);
      });

      it('returns a bundle', async () => {
        const b = await subject.notarize(artifact);

        expect(b).toBeTruthy();
        expect(b.mediaType).toEqual(
          'application/vnd.dev.sigstore.bundle+json;version=0.1'
        );

        assert(b.content?.$case === 'dsseEnvelope');
        expect(b.content?.dsseEnvelope).toBeTruthy();
        expect(b.content?.dsseEnvelope.payload).toEqual(artifact.data);
        expect(b.content.dsseEnvelope.payloadType).toEqual('');
        expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
        expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual(
          endorsement.key.hint
        );
        expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(
          endorsement.signature
        );

        expect(b.verificationMaterial).toBeTruthy();
        assert(b.verificationMaterial.content?.$case === 'publicKey');
        expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
        expect(b.verificationMaterial.content?.publicKey.hint).toEqual(
          endorsement.key.hint
        );
      });
    });

    describe('when the artifact type is provided', () => {
      const artifact = {
        data: Buffer.from('artifact'),
        type: 'text/plain',
      } satisfies Artifact;

      it('invokes the signatory', async () => {
        await subject.notarize(artifact);

        const expectedBlob = dsse.preAuthEncoding(artifact.type, artifact.data);
        expect(signatory.sign).toHaveBeenCalledWith(expectedBlob);
      });

      it('returns a bundle', async () => {
        const b = await subject.notarize(artifact);

        expect(b).toBeTruthy();
        expect(b.mediaType).toEqual(
          'application/vnd.dev.sigstore.bundle+json;version=0.1'
        );

        assert(b.content?.$case === 'dsseEnvelope');
        expect(b.content?.dsseEnvelope).toBeTruthy();
        expect(b.content?.dsseEnvelope.payload).toEqual(artifact.data);
        expect(b.content.dsseEnvelope.payloadType).toEqual(artifact.type);
        expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
        expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual(
          endorsement.key.hint
        );
        expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(
          endorsement.signature
        );

        expect(b.verificationMaterial).toBeTruthy();
        assert(b.verificationMaterial.content?.$case === 'publicKey');
        expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
        expect(b.verificationMaterial.content?.publicKey.hint).toEqual(
          endorsement.key.hint
        );
      });
    });
  });
});
