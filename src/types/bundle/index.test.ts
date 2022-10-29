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
import { Entry } from '../../tlog';
import { encoding as enc, pem } from '../../util';
import { Envelope, HashAlgorithm } from '../bundle';
import { SignatureMaterial } from '../signature';
import { bundle } from './index';

describe('bundle', () => {
  const signature = Buffer.from('signature');
  const certificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----`;

  const sigMaterial: SignatureMaterial = {
    signature,
    certificates: [certificate],
    key: undefined,
  };

  describe('toDSSEBundle', () => {
    const envelope: Envelope = {
      payloadType: 'application/vnd.in-toto+json',
      payload: Buffer.from('payload'),
      signatures: [
        {
          keyid: '',
          sig: signature,
        },
      ],
    };

    const entryKind = {
      kind: 'intoto',
      apiVersion: '0.0.2',
    };

    const rekorEntry: Entry = {
      uuid: 'a12bc3',
      body: enc.base64Encode(JSON.stringify(entryKind)),
      integratedTime: 1654015743,
      logID: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      logIndex: 2513258,
      verification: {
        signedEntryTimestamp: Buffer.from('set').toString('base64'),
        inclusionProof: {
          hashes: [],
          logIndex: 0,
          rootHash: '',
          treeSize: 0,
        },
      },
    };

    it('returns a valid DSSE bundle', () => {
      const b = bundle.toDSSEBundle(envelope, sigMaterial, rekorEntry);

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );
      if (b.content?.$case === 'dsseEnvelope') {
        expect(b.content.dsseEnvelope).toEqual(envelope);
      } else {
        fail('Expected dsseEnvelope');
      }

      // Verification material
      if (b.verificationMaterial?.content?.$case === 'x509CertificateChain') {
        const chain = b.verificationMaterial.content.x509CertificateChain;
        expect(chain).toBeTruthy();
        expect(chain.certificates).toHaveLength(1);
        expect(chain.certificates[0].derBytes).toEqual(pem.toDER(certificate));
      } else {
        fail('Expected x509CertificateChain');
      }

      // Timestamp verification data
      expect(b.verificationData).toBeTruthy();
      expect(b.verificationData?.timestampVerificationData).toBeTruthy();
      expect(
        b.verificationData?.timestampVerificationData?.rfc3161Timestamps
      ).toHaveLength(0);
      expect(b.verificationData?.tlogEntries).toHaveLength(1);

      const tlog = b.verificationData?.tlogEntries[0];
      expect(tlog?.inclusionPromise).toBeTruthy();
      expect(
        tlog?.inclusionPromise?.signedEntryTimestamp.toString('base64')
      ).toEqual(rekorEntry.verification.signedEntryTimestamp);
      expect(tlog?.integratedTime).toEqual(
        rekorEntry.integratedTime.toString()
      );
      expect(tlog?.logId).toBeTruthy();
      expect(tlog?.logId?.keyId).toBeTruthy();
      expect(tlog?.logId?.keyId.toString('hex')).toEqual(rekorEntry.logID);
      expect(tlog?.logIndex).toEqual(rekorEntry.logIndex.toString());
      expect(tlog?.inclusionProof).toBeFalsy();
      expect(tlog?.kindVersion?.kind).toEqual(entryKind.kind);
      expect(tlog?.kindVersion?.version).toEqual(entryKind.apiVersion);
    });
  });

  describe('toMessageSignatureBundle', () => {
    const digest = Buffer.from('digest');

    const entryKind = {
      kind: 'hashedrekord',
      apiVersion: '0.0.1',
    };

    const rekorEntry: Entry = {
      uuid: 'a12bc3',
      body: enc.base64Encode(JSON.stringify(entryKind)),
      integratedTime: 1654015743,
      logID: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      logIndex: 2513258,
      verification: {
        signedEntryTimestamp: Buffer.from('set').toString('base64'),
        inclusionProof: {
          hashes: [],
          logIndex: 0,
          rootHash: '',
          treeSize: 0,
        },
      },
    };

    it('returns a valid message signature bundle', () => {
      const b = bundle.toMessageSignatureBundle(
        digest,
        sigMaterial,
        rekorEntry
      );

      expect(b).toBeTruthy();
      expect(b.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );
      if (b.content?.$case === 'messageSignature') {
        expect(b.content.messageSignature.messageDigest?.algorithm).toEqual(
          HashAlgorithm.SHA2_256
        );
        expect(b.content.messageSignature.messageDigest?.digest).toEqual(
          digest
        );
        expect(b.content.messageSignature.signature).toEqual(signature);
      } else {
        fail('Expected messageSignature');
      }

      // Verification material
      if (b.verificationMaterial?.content?.$case === 'x509CertificateChain') {
        const chain = b.verificationMaterial.content.x509CertificateChain;
        expect(chain).toBeTruthy();
        expect(chain.certificates).toHaveLength(1);
        expect(chain.certificates[0].derBytes).toEqual(pem.toDER(certificate));
      } else {
        fail('Expected x509CertificateChain');
      }

      // Timestamp verification data
      expect(b.verificationData).toBeTruthy();
      expect(b.verificationData?.timestampVerificationData).toBeTruthy();
      expect(
        b.verificationData?.timestampVerificationData?.rfc3161Timestamps
      ).toHaveLength(0);
      expect(b.verificationData?.tlogEntries).toHaveLength(1);

      const tlog = b.verificationData?.tlogEntries[0];
      expect(tlog?.inclusionPromise).toBeTruthy();
      expect(
        tlog?.inclusionPromise?.signedEntryTimestamp.toString('base64')
      ).toEqual(rekorEntry.verification.signedEntryTimestamp);
      expect(tlog?.integratedTime).toEqual(
        rekorEntry.integratedTime.toString()
      );
      expect(tlog?.logId).toBeTruthy();
      expect(tlog?.logId?.keyId).toBeTruthy();
      expect(tlog?.logId?.keyId.toString('hex')).toEqual(rekorEntry.logID);
      expect(tlog?.logIndex).toEqual(rekorEntry.logIndex.toString());
      expect(tlog?.inclusionProof).toBeFalsy();
      expect(tlog?.kindVersion?.kind).toEqual(entryKind.kind);
      expect(tlog?.kindVersion?.version).toEqual(entryKind.apiVersion);
    });
  });
});
