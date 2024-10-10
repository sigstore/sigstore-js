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
import { toDSSEBundle, toMessageSignatureBundle } from '../../bundler/bundle';
import { crypto, pem } from '../../util';

import type { Artifact } from '../../bundler/base';
import type { Signature } from '../../signer';

const sigBytes = Buffer.from('signature');
const certificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----`;

const artifact = {
  type: 'application/json',
  data: Buffer.from('data'),
} satisfies Artifact;

describe('toMessageSignatureBundle', () => {
  const signature = {
    key: {
      $case: 'x509Certificate',
      certificate: certificate,
    },
    signature: sigBytes,
  } satisfies Signature;

  it('returns a valid message signature bundle', () => {
    const b = toMessageSignatureBundle(artifact, signature);

    expect(b).toBeTruthy();
    expect(b.mediaType).toEqual(
      'application/vnd.dev.sigstore.bundle+json;version=0.2'
    );

    assert(b.content?.$case === 'messageSignature');
    expect(b.content.messageSignature).toBeTruthy();
    expect(b.content.messageSignature.messageDigest.algorithm).toEqual(
      HashAlgorithm.SHA2_256
    );
    expect(b.content.messageSignature.messageDigest.digest).toEqual(
      crypto.digest('sha256', artifact.data)
    );
    expect(b.content.messageSignature.signature).toEqual(sigBytes);

    expect(b.verificationMaterial).toBeTruthy();
    assert(b.verificationMaterial.content?.$case === 'x509CertificateChain');
    expect(
      b.verificationMaterial.content?.x509CertificateChain.certificates
    ).toHaveLength(1);
    expect(
      b.verificationMaterial.content?.x509CertificateChain.certificates[0]
        .rawBytes
    ).toEqual(pem.toDER(certificate));
  });
});

describe('toDSSEBundle', () => {
  describe('when a public key w/ hint is provided', () => {
    const signature = {
      key: {
        $case: 'publicKey',
        publicKey: certificate,
        hint: 'hint',
      },
      signature: sigBytes,
    } satisfies Signature;

    it('returns a valid DSSE bundle', () => {
      const b = toDSSEBundle(artifact, signature);

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle.v0.3+json'
      );

      assert(b.content?.$case === 'dsseEnvelope');
      expect(b.content.dsseEnvelope).toBeTruthy();
      expect(b.content.dsseEnvelope.payloadType).toEqual(artifact.type);
      expect(b.content.dsseEnvelope.payload).toEqual(artifact.data);
      expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
      expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(sigBytes);
      expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual(
        signature.key.hint
      );

      expect(b.verificationMaterial).toBeTruthy();
      assert(b.verificationMaterial.content?.$case === 'publicKey');
      expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
      expect(b.verificationMaterial.content?.publicKey.hint).toEqual(
        signature.key.hint
      );
    });
  });

  describe('when a public key w/o hint is provided', () => {
    const signature = {
      key: {
        $case: 'publicKey',
        publicKey: certificate,
      },
      signature: sigBytes,
    } satisfies Signature;

    it('returns a valid DSSE bundle', () => {
      const b = toDSSEBundle(artifact, signature);

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle.v0.3+json'
      );

      assert(b.content?.$case === 'dsseEnvelope');
      expect(b.content.dsseEnvelope).toBeTruthy();
      expect(b.content.dsseEnvelope.payloadType).toEqual(artifact.type);
      expect(b.content.dsseEnvelope.payload).toEqual(artifact.data);
      expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
      expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(sigBytes);
      expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual('');

      expect(b.verificationMaterial).toBeTruthy();
      assert(b.verificationMaterial.content?.$case === 'publicKey');
      expect(b.verificationMaterial.content?.publicKey).toBeTruthy();
      expect(b.verificationMaterial.content?.publicKey.hint).toEqual('');
    });
  });

  describe('when a certificate chain provided', () => {
    const signature = {
      key: {
        $case: 'x509Certificate',
        certificate: certificate,
      },
      signature: sigBytes,
    } satisfies Signature;

    it('returns a valid DSSE bundle', () => {
      const b = toDSSEBundle(artifact, signature);

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle.v0.3+json'
      );

      assert(b.content?.$case === 'dsseEnvelope');
      expect(b.content.dsseEnvelope).toBeTruthy();
      expect(b.content.dsseEnvelope.payloadType).toEqual(artifact.type);
      expect(b.content.dsseEnvelope.payload).toEqual(artifact.data);
      expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
      expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(sigBytes);
      expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual('');

      expect(b.verificationMaterial).toBeTruthy();
      assert(b.verificationMaterial.content?.$case === 'certificate');
      expect(b.verificationMaterial.content?.certificate.rawBytes).toEqual(
        pem.toDER(certificate)
      );
    });
  });

  describe('when the certificate chain representation is requested', () => {
    const signature = {
      key: {
        $case: 'x509Certificate',
        certificate: certificate,
      },
      signature: sigBytes,
    } satisfies Signature;

    it('returns a valid DSSE bundle', () => {
      const b = toDSSEBundle(artifact, signature, true);

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.2'
      );

      assert(b.content?.$case === 'dsseEnvelope');
      expect(b.content.dsseEnvelope).toBeTruthy();
      expect(b.content.dsseEnvelope.payloadType).toEqual(artifact.type);
      expect(b.content.dsseEnvelope.payload).toEqual(artifact.data);
      expect(b.content.dsseEnvelope.signatures).toHaveLength(1);
      expect(b.content.dsseEnvelope.signatures[0].sig).toEqual(sigBytes);
      expect(b.content.dsseEnvelope.signatures[0].keyid).toEqual('');

      expect(b.verificationMaterial).toBeTruthy();
      assert(b.verificationMaterial.content?.$case === 'x509CertificateChain');
      expect(
        b.verificationMaterial.content?.x509CertificateChain.certificates[0]
          .rawBytes
      ).toEqual(pem.toDER(certificate));
    });
  });
});
