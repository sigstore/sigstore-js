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
import { DSSEBundleBuilder } from '../../bundler/dsse';
import { dsse } from '../../util';

import type { Artifact } from '../../bundler';
import type { Signature, Signer } from '../../signer';

describe('DSSEBundleBuilder', () => {
  // Signature fixture to return from fake signer
  const sigBytes = Buffer.from('signature');
  const key = 'publickey';

  const signature = {
    key: {
      $case: 'publicKey',
      publicKey: key,
      hint: 'hint',
    },
    signature: sigBytes,
  } satisfies Signature;

  const signer = {
    sign: jest.fn().mockResolvedValue(signature),
  } satisfies Signer;

  describe('constructor', () => {
    it('should create a new instance', () => {
      const bundler = new DSSEBundleBuilder({ signer: signer, witnesses: [] });
      expect(bundler).toBeDefined();
    });
  });

  describe('#create', () => {
    const subject = new DSSEBundleBuilder({ signer: signer, witnesses: [] });

    describe('when the artifact type is NOT provided', () => {
      const artifact: Artifact = {
        data: Buffer.from('artifact'),
      };

      it('invokes the signer', async () => {
        await subject.create(artifact);

        const expectedBlob = dsse.preAuthEncoding('', artifact.data);
        expect(signer.sign).toHaveBeenCalledWith(expectedBlob);
      });

      it('returns a bundle', async () => {
        const b = await subject.create(artifact);

        expect(b).toBeTruthy();
        expect(b.mediaType).toEqual(
          'application/vnd.dev.sigstore.bundle+json;version=0.2'
        );

        expect(b.content.dsseEnvelope).toBeTruthy();
        expect(b.content.dsseEnvelope.payload).toEqual(artifact.data);
        expect(b.content.dsseEnvelope.payloadType).toEqual('');
        expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
        expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual(
          signature.key.hint
        );
        expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(
          signature.signature
        );

        expect(b.verificationMaterial).toBeTruthy();
        assert(b.verificationMaterial.content?.$case === 'publicKey');
        expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
        expect(b.verificationMaterial.content?.publicKey.hint).toEqual(
          signature.key.hint
        );
      });
    });

    describe('when the artifact type is provided', () => {
      const artifact = {
        data: Buffer.from('artifact'),
        type: 'text/plain',
      } satisfies Artifact;

      it('invokes the signer', async () => {
        await subject.create(artifact);

        const expectedBlob = dsse.preAuthEncoding(artifact.type, artifact.data);
        expect(signer.sign).toHaveBeenCalledWith(expectedBlob);
      });

      it('returns a bundle', async () => {
        const b = await subject.create(artifact);

        expect(b).toBeTruthy();
        expect(b.mediaType).toEqual(
          'application/vnd.dev.sigstore.bundle+json;version=0.2'
        );

        expect(b.content.dsseEnvelope).toBeTruthy();
        expect(b.content.dsseEnvelope.payload).toEqual(artifact.data);
        expect(b.content.dsseEnvelope.payloadType).toEqual(artifact.type);
        expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
        expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual(
          signature.key.hint
        );
        expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(
          signature.signature
        );

        expect(b.verificationMaterial).toBeTruthy();
        assert(b.verificationMaterial.content?.$case === 'publicKey');
        expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
        expect(b.verificationMaterial.content?.publicKey.hint).toEqual(
          signature.key.hint
        );
      });
    });
  });
});
