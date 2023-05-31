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
import * as sigstore from '@sigstore/bundle';
import { HashAlgorithm } from '@sigstore/protobuf-specs';
import assert from 'assert';
import { toMessageSignatureBundle } from '../../notary/bundle';
import { Artifact, BaseNotary } from '../../notary/notary';
import { Endorsement, Signatory } from '../../signatory';
import { crypto, pem } from '../../util';
import { Affidavit, Witness } from '../../witness';

describe('BaseNotary', () => {
  const artifact: Artifact = {
    data: Buffer.from('data'),
  };

  // Endorsement fixture to return from fake Signatory
  const signature = Buffer.from('signature');
  const key = 'publickey';

  const publicKeyEndorsement = {
    key: {
      $case: 'publicKey',
      publicKey: key,
      hint: 'hint',
    },
    signature: signature,
  } satisfies Endorsement;

  const fakePublicKeySignatory = {
    sign: jest.fn().mockResolvedValue(publicKeyEndorsement),
  } satisfies Signatory;

  const certificateEndorsement = {
    key: {
      $case: 'x509Certificate',
      certificate: key,
    },
    signature: signature,
  } satisfies Endorsement;

  const fakeCertificateSignatory = {
    sign: jest.fn().mockResolvedValue(certificateEndorsement),
  } satisfies Signatory;

  // VerificationMaterial fixture to return from fake Witness
  const timestamp = Buffer.from('timestamp');
  const timestampAffidavit: Affidavit = {
    rfc3161Timestamps: [{ signedTimestamp: timestamp }],
  };

  const fakeTSAWitness: Witness = {
    testify: jest.fn().mockResolvedValue(timestampAffidavit),
  };

  const tlogAffidavit: Affidavit = {
    tlogEntries: [
      {
        logIndex: '1234',
        logId: {
          keyId: Buffer.from('keyId'),
        },
        kindVersion: {
          kind: 'hashedrekord',
          version: '0.0.1',
        },
        integratedTime: '123456789',
        inclusionProof: undefined,
        inclusionPromise: {
          signedEntryTimestamp: Buffer.from('set'),
        },
        canonicalizedBody: Buffer.from('body'),
      },
    ],
  };

  const fakeRekorWitness: Witness = {
    testify: jest.fn().mockResolvedValue(tlogAffidavit),
  };

  class FakeNotary extends BaseNotary {
    protected override async package(
      artifact: Artifact,
      endorsement: Endorsement
    ): Promise<sigstore.Bundle> {
      return toMessageSignatureBundle(artifact, endorsement);
    }
  }

  describe('notarize', () => {
    afterEach(() => {
      jest.clearAllMocks();
    });

    describe('when configured with a public key signatory', () => {
      const subject = new FakeNotary({
        signatory: fakePublicKeySignatory,
        witnesses: [fakeTSAWitness, fakeRekorWitness],
      });

      it('invokes the signatory', async () => {
        await subject.notarize(artifact);
        expect(fakePublicKeySignatory.sign).toBeCalledWith(artifact.data);
      });

      it('invokes the witnesses', async () => {
        await subject.notarize(artifact);

        const expectedContent: sigstore.Bundle['content'] = {
          $case: 'messageSignature',
          messageSignature: {
            messageDigest: {
              algorithm: HashAlgorithm.SHA2_256,
              digest: crypto.hash(artifact.data),
            },
            signature: expect.anything(),
          },
        };

        expect(fakeTSAWitness.testify).toBeCalledWith(
          expectedContent,
          publicKeyEndorsement.key.publicKey
        );

        expect(fakeRekorWitness.testify).toBeCalledWith(
          expectedContent,
          publicKeyEndorsement.key.publicKey
        );
      });

      it('returns a valid bundle', async () => {
        const bundle = await subject.notarize(artifact);

        expect(bundle).toBeTruthy();
        expect(bundle.mediaType).toEqual(
          'application/vnd.dev.sigstore.bundle+json;version=0.1'
        );
        expect(bundle.content).toBeTruthy();
        expect(bundle.verificationMaterial).toBeTruthy();

        // Content - MessageSignature
        assert(bundle.content?.$case === 'messageSignature');
        expect(bundle.content.messageSignature).toBeTruthy();
        expect(bundle.content.messageSignature.signature).toEqual(signature);
        expect(bundle.content.messageSignature.messageDigest).toBeTruthy();
        expect(
          bundle.content.messageSignature?.messageDigest?.algorithm
        ).toEqual(HashAlgorithm.SHA2_256);
        expect(bundle.content.messageSignature?.messageDigest?.digest).toEqual(
          crypto.hash(artifact.data)
        );

        // VerificationMaterial - Content
        expect(bundle.verificationMaterial?.content).toBeTruthy();
        assert(bundle.verificationMaterial?.content?.$case === 'publicKey');
        expect(bundle.verificationMaterial?.content?.publicKey).toBeTruthy();
        expect(bundle.verificationMaterial?.content?.publicKey.hint).toEqual(
          publicKeyEndorsement.key.hint
        );

        // VerificationMaterial - TimestampVerificationData
        expect(
          bundle.verificationMaterial.timestampVerificationData
        ).toBeTruthy();
        expect(
          bundle.verificationMaterial.timestampVerificationData
            ?.rfc3161Timestamps
        ).toBeTruthy();
        expect(
          bundle.verificationMaterial.timestampVerificationData
            ?.rfc3161Timestamps
        ).toHaveLength(1);
        expect(
          bundle.verificationMaterial.timestampVerificationData
            ?.rfc3161Timestamps?.[0].signedTimestamp
        ).toEqual(timestamp);

        // VerificationMaterial - TlogEntries
        expect(bundle.verificationMaterial.tlogEntries).toBeTruthy();
        expect(bundle.verificationMaterial.tlogEntries).toHaveLength(1);
        expect(bundle.verificationMaterial.tlogEntries).toEqual(
          tlogAffidavit.tlogEntries
        );
      });
    });

    describe('when configured with a certificate signatory', () => {
      const subject = new FakeNotary({
        signatory: fakeCertificateSignatory,
        witnesses: [fakeRekorWitness, fakeTSAWitness],
      });

      it('invokes the signatory', async () => {
        await subject.notarize(artifact);
        expect(fakeCertificateSignatory.sign).toBeCalledWith(artifact.data);
      });

      it('invokes the witness', async () => {
        await subject.notarize(artifact);

        const expectedContent: sigstore.Bundle['content'] = {
          $case: 'messageSignature',
          messageSignature: {
            messageDigest: {
              algorithm: HashAlgorithm.SHA2_256,
              digest: crypto.hash(artifact.data),
            },
            signature: expect.anything(),
          },
        };

        expect(fakeTSAWitness.testify).toBeCalledWith(
          expectedContent,
          publicKeyEndorsement.key.publicKey
        );

        expect(fakeRekorWitness.testify).toBeCalledWith(
          expectedContent,
          publicKeyEndorsement.key.publicKey
        );
      });

      it('returns a valid bundle', async () => {
        const bundle = await subject.notarize(artifact);

        expect(bundle).toBeTruthy();
        expect(bundle.mediaType).toEqual(
          'application/vnd.dev.sigstore.bundle+json;version=0.1'
        );
        expect(bundle.content).toBeTruthy();
        expect(bundle.verificationMaterial).toBeTruthy();

        // Content - MessageSignature
        assert(bundle.content?.$case === 'messageSignature');
        expect(bundle.content.messageSignature).toBeTruthy();
        expect(bundle.content.messageSignature.signature).toEqual(signature);
        expect(bundle.content.messageSignature.messageDigest).toBeTruthy();
        expect(
          bundle.content.messageSignature?.messageDigest?.algorithm
        ).toEqual(HashAlgorithm.SHA2_256);
        expect(bundle.content.messageSignature?.messageDigest?.digest).toEqual(
          crypto.hash(artifact.data)
        );

        // VerificationMaterial - Content
        expect(bundle.verificationMaterial?.content).toBeTruthy();
        assert(
          bundle.verificationMaterial?.content?.$case === 'x509CertificateChain'
        );
        expect(
          bundle.verificationMaterial?.content?.x509CertificateChain
        ).toBeTruthy();
        expect(
          bundle.verificationMaterial?.content?.x509CertificateChain
            .certificates
        ).toHaveLength(1);
        expect(
          bundle.verificationMaterial?.content?.x509CertificateChain
            .certificates[0].rawBytes
        ).toEqual(pem.toDER(key));

        // VerificationMaterial - TimestampVerificationData
        expect(
          bundle.verificationMaterial.timestampVerificationData
        ).toBeTruthy();
        expect(
          bundle.verificationMaterial.timestampVerificationData
            ?.rfc3161Timestamps
        ).toBeTruthy();
        expect(
          bundle.verificationMaterial.timestampVerificationData
            ?.rfc3161Timestamps
        ).toHaveLength(1);
        expect(
          bundle.verificationMaterial.timestampVerificationData
            ?.rfc3161Timestamps?.[0].signedTimestamp
        ).toEqual(timestamp);

        // VerificationMaterial - TlogEntries
        expect(bundle.verificationMaterial.tlogEntries).toBeTruthy();
        expect(bundle.verificationMaterial.tlogEntries).toHaveLength(1);
        expect(bundle.verificationMaterial.tlogEntries).toEqual(
          tlogAffidavit.tlogEntries
        );
      });
    });

    describe('when configured with multiple witnesses of the same type', () => {
      const subject = new FakeNotary({
        signatory: fakePublicKeySignatory,
        witnesses: [
          fakeTSAWitness,
          fakeRekorWitness,
          fakeTSAWitness,
          fakeRekorWitness,
        ],
      });

      it('invokes the witnesses the correct number of times', async () => {
        await subject.notarize(artifact);

        expect(fakeTSAWitness.testify).toBeCalledTimes(2);
        expect(fakeRekorWitness.testify).toBeCalledTimes(2);
      });

      it('returns a bundle with all the verification material', async () => {
        const bundle = await subject.notarize(artifact);

        expect(bundle).toBeTruthy();
        expect(bundle.verificationMaterial?.tlogEntries).toHaveLength(2);
        expect(
          bundle.verificationMaterial?.timestampVerificationData
            ?.rfc3161Timestamps
        ).toHaveLength(2);
      });
    });
  });
});
