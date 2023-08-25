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
import { HashAlgorithm } from '@sigstore/protobuf-specs';
import assert from 'assert';
import { toDSSEBundle, toMessageSignatureBundle } from '../build';
import { BUNDLE_V02_MEDIA_TYPE } from '../bundle';

const signature = Buffer.from('signature');
const keyHint = 'hint';
const certificate = Buffer.from('certificate');

describe('toMessageSignatureBundle', () => {
  const digest = Buffer.from('digest');
  it('returns a valid message signature bundle', () => {
    const b = toMessageSignatureBundle({
      digest,
      signature,
      certificate,
      keyHint,
    });

    expect(b).toBeTruthy();
    expect(b.mediaType).toEqual(BUNDLE_V02_MEDIA_TYPE);

    assert(b.content?.$case === 'messageSignature');
    expect(b.content.messageSignature).toBeTruthy();
    expect(b.content.messageSignature.messageDigest.algorithm).toEqual(
      HashAlgorithm.SHA2_256
    );
    expect(b.content.messageSignature.messageDigest.digest).toEqual(digest);
    expect(b.content.messageSignature.signature).toEqual(signature);

    expect(b.verificationMaterial).toBeTruthy();
    assert(b.verificationMaterial.content?.$case === 'x509CertificateChain');
    expect(
      b.verificationMaterial.content?.x509CertificateChain.certificates
    ).toHaveLength(1);
    expect(
      b.verificationMaterial.content?.x509CertificateChain.certificates[0]
        .rawBytes
    ).toEqual(certificate);
  });
});

describe('toDSSEBundle', () => {
  const artifact = Buffer.from('data');
  const artifactType = 'text/plain';

  describe('when a public key w/ hint is provided', () => {
    it('returns a valid DSSE bundle', () => {
      const b = toDSSEBundle({
        artifact,
        artifactType,
        signature,
        keyHint,
      });

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(BUNDLE_V02_MEDIA_TYPE);

      assert(b.content?.$case === 'dsseEnvelope');
      expect(b.content.dsseEnvelope).toBeTruthy();
      expect(b.content.dsseEnvelope.payloadType).toEqual(artifactType);
      expect(b.content.dsseEnvelope.payload).toEqual(artifact);
      expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
      expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(signature);
      expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual(keyHint);

      expect(b.verificationMaterial).toBeTruthy();
      assert(b.verificationMaterial.content?.$case === 'publicKey');
      expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
      expect(b.verificationMaterial.content?.publicKey.hint).toEqual(keyHint);
    });
  });

  describe('when a public key w/o hint is provided', () => {
    it('returns a valid DSSE bundle', () => {
      const b = toDSSEBundle({
        artifact,
        artifactType,
        signature,
      });

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(BUNDLE_V02_MEDIA_TYPE);

      assert(b.content?.$case === 'dsseEnvelope');
      expect(b.content.dsseEnvelope).toBeTruthy();
      expect(b.content.dsseEnvelope.payloadType).toEqual(artifactType);
      expect(b.content.dsseEnvelope.payload).toEqual(artifact);
      expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
      expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(signature);
      expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual('');

      expect(b.verificationMaterial).toBeTruthy();
      assert(b.verificationMaterial.content?.$case === 'publicKey');
      expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
      expect(b.verificationMaterial.content?.publicKey.hint).toEqual('');
    });
  });

  describe('when a certificate chain provided', () => {
    it('returns a valid DSSE bundle', () => {
      const b = toDSSEBundle({
        artifact,
        artifactType,
        signature,
        certificate,
      });

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(BUNDLE_V02_MEDIA_TYPE);

      assert(b.content?.$case === 'dsseEnvelope');
      expect(b.content.dsseEnvelope).toBeTruthy();
      expect(b.content.dsseEnvelope.payloadType).toEqual(artifactType);
      expect(b.content.dsseEnvelope.payload).toEqual(artifact);
      expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
      expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(signature);
      expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual('');

      expect(b.verificationMaterial).toBeTruthy();
      assert(b.verificationMaterial.content?.$case === 'x509CertificateChain');
      expect(
        b.verificationMaterial.content?.x509CertificateChain.certificates
      ).toHaveLength(1);
      expect(
        b.verificationMaterial.content?.x509CertificateChain.certificates[0]
          .rawBytes
      ).toEqual(certificate);
    });
  });
});
