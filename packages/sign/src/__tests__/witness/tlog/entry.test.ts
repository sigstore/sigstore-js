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
import { encoding as enc } from '../../../util';
import { toProposedEntry } from '../../../witness/tlog/entry';

import { envelopeToJSON } from '@sigstore/bundle';
import type { SignatureBundle } from '../../../witness';

describe('toProposedEntry', () => {
  const publicKey = '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----';
  const signature = Buffer.from('signature');

  describe('when a message signature is provided', () => {
    const sigBundle: SignatureBundle = {
      $case: 'messageSignature',
      messageSignature: {
        signature: signature,
        messageDigest: {
          algorithm: HashAlgorithm.SHA2_256,
          digest: Buffer.from('digest'),
        },
      },
    };

    it('returns a valid ProposedEntry entry', () => {
      const entry = toProposedEntry(sigBundle, publicKey);

      assert(entry.apiVersion === '0.0.1');
      assert(entry.kind === 'hashedrekord');
      expect(entry.spec).toBeTruthy();

      expect(entry.spec.data).toBeTruthy();
      expect(entry.spec.data.hash).toBeTruthy();
      expect(entry.spec.data.hash?.algorithm).toBe('sha256');
      expect(entry.spec.data.hash?.value).toBe(
        sigBundle.messageSignature.messageDigest.digest.toString('hex')
      );

      expect(entry.spec.signature).toBeTruthy();
      expect(entry.spec.signature?.content).toBe(signature.toString('base64'));
      expect(entry.spec.signature?.publicKey).toBeTruthy();
      expect(entry.spec.signature?.publicKey?.content).toBe(
        enc.base64Encode(publicKey)
      );
    });
  });

  describe('when a DSSE envelope is provided', () => {
    const sigBundle: SignatureBundle = {
      $case: 'dsseEnvelope',
      dsseEnvelope: {
        signatures: [{ keyid: '123', sig: signature }],
        payloadType: 'application/vnd.in-toto+json',
        payload: Buffer.from('payload'),
      },
    };

    it('return a valid ProposedEntry entry', () => {
      const entry = toProposedEntry(sigBundle, publicKey);

      assert(entry.apiVersion === '0.0.1');
      assert(entry.kind === 'dsse');
      expect(entry.spec).toBeTruthy();
      expect(entry.spec.proposedContent).toBeTruthy();

      const e = entry.spec.proposedContent?.envelope;
      expect(e).toEqual(JSON.stringify(envelopeToJSON(sigBundle.dsseEnvelope)));

      expect(entry.spec.proposedContent?.verifiers).toHaveLength(1);
      expect(entry.spec.proposedContent?.verifiers[0]).toEqual(
        enc.base64Encode(publicKey)
      );
    });
  });
});
