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
import { SerializedBundle } from './serialized';
import { Envelope } from './__generated__/envelope';
import { Bundle, VerificationData } from './__generated__/sigstore_bundle';
import {
  HashAlgorithm,
  hashAlgorithmToJSON,
  MessageSignature,
  X509CertificateChain,
} from './__generated__/sigstore_common';

describe('Serialized Types', () => {
  const verificationData: VerificationData = {
    tlogEntries: [
      {
        logIndex: '0',
        logId: {
          keyId: Buffer.from('logId'),
        },
        kindVersion: {
          kind: 'kind',
          version: 'version',
        },
        integratedTime: '2021-01-01T00:00:00Z',
        inclusionPromise: {
          signedEntryTimestamp: Buffer.from('inclusionPromise'),
        },
        inclusionProof: {
          logIndex: '0',
          rootHash: Buffer.from('rootHash'),
          treeSize: '0',
          hashes: [Buffer.from('hash')],
          checkpoint: {
            envelope: 'checkpoint',
          },
        },
      },
    ],
    timestampVerificationData: {
      rfc3161Timestamps: [{ signedTimestamp: Buffer.from('signedTimestamp') }],
    },
  };

  const x509CertificateChain: X509CertificateChain = {
    certificates: [{ derBytes: Buffer.from('certificate') }],
  };

  describe('SerializedDSSEBundle', () => {
    const dsseEnvelope: Envelope = {
      payload: Buffer.from('payload'),
      payloadType: 'application/vnd.in-toto+json',
      signatures: [
        {
          keyid: 'keyid',
          sig: Buffer.from('signature'),
        },
      ],
    };

    const dsseBundle: Bundle = {
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope,
      },
      verificationData,
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain,
        },
      },
    };

    it('matches the serialized form of the Bundle', () => {
      const json = Bundle.toJSON(dsseBundle) as SerializedBundle;

      expect(json.mediaType).toEqual(dsseBundle.mediaType);
      expect(json.verificationMaterial).toBeTruthy();
      expect(json.verificationMaterial?.x509CertificateChain).toBeTruthy();
      expect(
        json.verificationMaterial?.x509CertificateChain?.certificates
      ).toHaveLength(x509CertificateChain.certificates.length);

      const cert =
        json.verificationMaterial?.x509CertificateChain?.certificates[0];
      expect(cert?.derBytes).toEqual(
        Buffer.from(x509CertificateChain.certificates[0].derBytes).toString(
          'base64'
        )
      );

      expect(json.verificationData).toBeTruthy();
      expect(json.verificationData?.tlogEntries).toHaveLength(
        verificationData.tlogEntries.length
      );

      const tlogEntry = json.verificationData?.tlogEntries[0];
      const expectedTlogEntry = verificationData.tlogEntries[0];
      expect(tlogEntry).toBeTruthy();
      expect(tlogEntry?.logId).toBeTruthy();
      expect(tlogEntry?.logId.keyId).toEqual(
        (expectedTlogEntry.logId?.keyId as Buffer).toString('base64')
      );
      expect(tlogEntry?.logIndex).toEqual(expectedTlogEntry.logIndex);
      expect(tlogEntry?.kindVersion).toBeTruthy();
      expect(tlogEntry?.kindVersion?.kind).toEqual(
        expectedTlogEntry.kindVersion?.kind
      );
      expect(tlogEntry?.kindVersion?.version).toEqual(
        expectedTlogEntry.kindVersion?.version
      );
      expect(tlogEntry?.integratedTime).toEqual(
        expectedTlogEntry.integratedTime
      );
      expect(tlogEntry?.inclusionPromise).toBeTruthy();
      expect(tlogEntry?.inclusionPromise.signedEntryTimestamp).toEqual(
        (
          expectedTlogEntry.inclusionPromise?.signedEntryTimestamp as Buffer
        ).toString('base64')
      );
      expect(tlogEntry?.inclusionProof).toBeTruthy();
      expect(tlogEntry?.inclusionProof?.logIndex).toEqual(
        expectedTlogEntry.inclusionProof?.logIndex
      );
      expect(tlogEntry?.inclusionProof?.rootHash).toEqual(
        (expectedTlogEntry.inclusionProof?.rootHash as Buffer).toString(
          'base64'
        )
      );
      expect(tlogEntry?.inclusionProof?.treeSize).toEqual(
        expectedTlogEntry.inclusionProof?.treeSize
      );
      expect(tlogEntry?.inclusionProof?.hashes).toHaveLength(
        expectedTlogEntry.inclusionProof?.hashes?.length as number
      );
      const hash = tlogEntry?.inclusionProof?.hashes[0];
      const expectedHash = expectedTlogEntry.inclusionProof?.hashes?.[0];
      expect(hash).toEqual((expectedHash as Buffer).toString('base64'));
      expect(tlogEntry?.inclusionProof?.checkpoint).toBeTruthy();
      expect(tlogEntry?.inclusionProof?.checkpoint.envelope).toEqual(
        expectedTlogEntry.inclusionProof?.checkpoint?.envelope
      );

      expect(json.verificationData?.timestampVerificationData).toBeTruthy();
      expect(
        json.verificationData?.timestampVerificationData.rfc3161Timestamps
      ).toHaveLength(
        verificationData.timestampVerificationData?.rfc3161Timestamps
          ?.length as number
      );
      const rfc3161Timestamp =
        json.verificationData?.timestampVerificationData.rfc3161Timestamps[0];
      const expectedRfc3161Timestamp =
        verificationData.timestampVerificationData?.rfc3161Timestamps?.[0];
      expect(rfc3161Timestamp).toBeTruthy();
      expect(rfc3161Timestamp?.signedTimestamp).toEqual(
        (expectedRfc3161Timestamp?.signedTimestamp as Buffer).toString('base64')
      );

      expect(json.dsseEnvelope).toBeTruthy();
      expect(json.dsseEnvelope?.payload).toEqual(
        dsseEnvelope.payload.toString('base64')
      );
      expect(json.dsseEnvelope?.payloadType).toEqual(dsseEnvelope.payloadType);
      expect(json.dsseEnvelope?.signatures).toHaveLength(
        dsseEnvelope.signatures.length
      );
      const signature = json.dsseEnvelope?.signatures[0];
      const expectedSignature = dsseEnvelope.signatures[0];
      expect(signature).toBeTruthy();
      expect(signature?.keyid).toEqual(expectedSignature.keyid);
      expect(signature?.sig).toEqual(expectedSignature.sig.toString('base64'));
    });
  });

  describe('SerializedMessageSignatureBundle', () => {
    const messageSignature: MessageSignature = {
      messageDigest: {
        digest: Buffer.from('digest'),
        algorithm: 1,
      },
      signature: Buffer.from('signature'),
    };

    const messageSignatureBundle: Bundle = {
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'messageSignature',
        messageSignature,
      },
      verificationData,
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain,
        },
      },
    };

    it('matches the serialized form of the Bundle', () => {
      const json = Bundle.toJSON(messageSignatureBundle) as SerializedBundle;

      expect(json.mediaType).toEqual(messageSignatureBundle.mediaType);
      expect(json.verificationMaterial).toBeTruthy();
      expect(json.verificationMaterial?.x509CertificateChain).toBeTruthy();
      expect(
        json.verificationMaterial?.x509CertificateChain?.certificates
      ).toHaveLength(x509CertificateChain.certificates.length);

      const cert =
        json.verificationMaterial?.x509CertificateChain?.certificates[0];
      expect(cert?.derBytes).toEqual(
        Buffer.from(x509CertificateChain.certificates[0].derBytes).toString(
          'base64'
        )
      );

      expect(json.verificationData).toBeTruthy();
      expect(json.verificationData?.tlogEntries).toHaveLength(
        verificationData.tlogEntries.length
      );

      const tlogEntry = json.verificationData?.tlogEntries[0];
      const expectedTlogEntry = verificationData.tlogEntries[0];
      expect(tlogEntry).toBeTruthy();
      expect(tlogEntry?.logId).toBeTruthy();
      expect(tlogEntry?.logId.keyId).toEqual(
        (expectedTlogEntry.logId?.keyId as Buffer).toString('base64')
      );
      expect(tlogEntry?.logIndex).toEqual(expectedTlogEntry.logIndex);
      expect(tlogEntry?.kindVersion).toBeTruthy();
      expect(tlogEntry?.kindVersion?.kind).toEqual(
        expectedTlogEntry.kindVersion?.kind
      );
      expect(tlogEntry?.kindVersion?.version).toEqual(
        expectedTlogEntry.kindVersion?.version
      );
      expect(tlogEntry?.integratedTime).toEqual(
        expectedTlogEntry.integratedTime
      );
      expect(tlogEntry?.inclusionPromise).toBeTruthy();
      expect(tlogEntry?.inclusionPromise.signedEntryTimestamp).toEqual(
        (
          expectedTlogEntry.inclusionPromise?.signedEntryTimestamp as Buffer
        ).toString('base64')
      );
      expect(tlogEntry?.inclusionProof).toBeTruthy();
      expect(tlogEntry?.inclusionProof?.logIndex).toEqual(
        expectedTlogEntry.inclusionProof?.logIndex
      );
      expect(tlogEntry?.inclusionProof?.rootHash).toEqual(
        (expectedTlogEntry.inclusionProof?.rootHash as Buffer).toString(
          'base64'
        )
      );
      expect(tlogEntry?.inclusionProof?.treeSize).toEqual(
        expectedTlogEntry.inclusionProof?.treeSize
      );
      expect(tlogEntry?.inclusionProof?.hashes).toHaveLength(
        expectedTlogEntry.inclusionProof?.hashes?.length as number
      );
      const hash = tlogEntry?.inclusionProof?.hashes[0];
      const expectedHash = expectedTlogEntry.inclusionProof?.hashes?.[0];
      expect(hash).toEqual((expectedHash as Buffer).toString('base64'));
      expect(tlogEntry?.inclusionProof?.checkpoint).toBeTruthy();
      expect(tlogEntry?.inclusionProof?.checkpoint.envelope).toEqual(
        expectedTlogEntry.inclusionProof?.checkpoint?.envelope
      );

      expect(json.verificationData?.timestampVerificationData).toBeTruthy();
      expect(
        json.verificationData?.timestampVerificationData.rfc3161Timestamps
      ).toHaveLength(
        verificationData.timestampVerificationData?.rfc3161Timestamps
          ?.length as number
      );
      const rfc3161Timestamp =
        json.verificationData?.timestampVerificationData.rfc3161Timestamps[0];
      const expectedRfc3161Timestamp =
        verificationData.timestampVerificationData?.rfc3161Timestamps?.[0];
      expect(rfc3161Timestamp).toBeTruthy();
      expect(rfc3161Timestamp?.signedTimestamp).toEqual(
        (expectedRfc3161Timestamp?.signedTimestamp as Buffer).toString('base64')
      );

      expect(json.messageSignature).toBeTruthy();
      expect(json.messageSignature?.messageDigest).toBeTruthy();
      expect(json.messageSignature?.messageDigest?.digest).toEqual(
        (messageSignature.messageDigest?.digest as Buffer).toString('base64')
      );
      expect(json.messageSignature?.messageDigest?.algorithm).toEqual(
        hashAlgorithmToJSON(
          messageSignature.messageDigest?.algorithm as HashAlgorithm
        )
      );

      expect(json.messageSignature?.signature).toEqual(
        (messageSignature.signature as Buffer).toString('base64')
      );
    });
  });
});
