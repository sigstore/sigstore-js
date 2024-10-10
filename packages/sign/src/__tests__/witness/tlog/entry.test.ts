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
import { envelopeToJSON } from '@sigstore/bundle';
import { HashAlgorithm } from '@sigstore/protobuf-specs';
import assert from 'assert';
import { crypto, encoding as enc } from '../../../util';
import { toProposedEntry } from '../../../witness/tlog/entry';

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
    describe('when the keyid is a non-empty string', () => {
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
        expect(entry.spec.proposedContent?.envelope).toEqual(
          JSON.stringify(envelopeToJSON(sigBundle.dsseEnvelope))
        );
        expect(entry.spec.proposedContent?.verifiers).toHaveLength(1);
        expect(entry.spec.proposedContent?.verifiers[0]).toEqual(
          enc.base64Encode(publicKey)
        );
      });
    });

    describe('when the keyid is an empty string', () => {
      const sigBundle: SignatureBundle = {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          signatures: [{ keyid: '', sig: signature }],
          payloadType: 'application/vnd.in-toto+json',
          payload: Buffer.from('payload'),
        },
      };

      it('return a valid ProposedEntry entry', () => {
        const entry = toProposedEntry(sigBundle, publicKey, 'intoto');

        assert(entry.apiVersion === '0.0.2');
        assert(entry.kind === 'intoto');
        expect(entry.spec).toBeTruthy();
        expect(entry.spec.content).toBeTruthy();
        expect(entry.spec.content.envelope).toBeTruthy();

        const e = entry.spec.content.envelope;
        expect(e?.payloadType).toEqual(sigBundle.dsseEnvelope.payloadType);
        expect(e?.payload).toEqual(
          enc.base64Encode(sigBundle.dsseEnvelope.payload.toString('base64'))
        );
        expect(e?.signatures).toHaveLength(1);
        expect(e?.signatures[0].keyid).toBeUndefined();
        expect(e?.signatures[0].sig).toEqual(
          enc.base64Encode(
            sigBundle.dsseEnvelope.signatures[0].sig.toString('base64')
          )
        );
        expect(e?.signatures[0].publicKey).toEqual(enc.base64Encode(publicKey));

        expect(entry.spec.content.payloadHash).toBeTruthy();
        expect(entry.spec.content.payloadHash?.algorithm).toBe('sha256');
        expect(entry.spec.content.payloadHash?.value).toBe(
          crypto
            .digest('sha256', sigBundle.dsseEnvelope.payload)
            .toString('hex')
        );
        expect(entry.spec.content.hash).toBeTruthy();
        expect(entry.spec.content.hash?.algorithm).toBe('sha256');

        // This hard-coded hash value helps us detect if we've unintentionally
        // changed the hashing algorithm.
        expect(entry.spec.content.hash?.value).toBe(
          'f39ab279af9d9be421342ce4c8e5c422b5bc3dd20602703b1893283a934fbe72'
        );
      });
    });

    describe('when there are multiple signatures in the envelope', () => {
      const sigBundle: SignatureBundle = {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          signatures: [
            { keyid: '123', sig: signature },
            { keyid: '', sig: signature },
          ],
          payloadType: 'application/vnd.in-toto+json',
          payload: Buffer.from('payload'),
        },
      };

      describe('when asking for an intoto entry', () => {
        it('return a valid ProposedEntry entry', () => {
          const entry = toProposedEntry(sigBundle, publicKey, 'intoto');

          assert(entry.apiVersion === '0.0.2');
          assert(entry.kind === 'intoto');

          // Check to ensure only the first signature is included in the envelope
          const e = entry.spec.content.envelope;
          expect(e?.signatures).toHaveLength(1);
          expect(e?.signatures[0].keyid).toEqual(
            sigBundle.dsseEnvelope.signatures[0].keyid
          );
          expect(e?.signatures[0].sig).toEqual(
            enc.base64Encode(
              sigBundle.dsseEnvelope.signatures[0].sig.toString('base64')
            )
          );
          expect(e?.signatures[0].publicKey).toEqual(
            enc.base64Encode(publicKey)
          );

          // This hard-coded hash value helps us detect if we've unintentionally
          // changed the hashing algorithm.
          expect(entry.spec.content.hash?.value).toBe(
            '37d47ab456ca63a84f6457be655dd49799542f2e1db5d05160b214fb0b9a7f55'
          );
        });
      });

      describe('when asking for a dsse entry', () => {
        it('return a valid ProposedEntry entry', () => {
          const entry = toProposedEntry(sigBundle, publicKey, 'dsse');

          assert(entry.apiVersion === '0.0.1');
          assert(entry.kind === 'dsse');

          expect(entry.spec.proposedContent).toBeTruthy();
          expect(entry.spec.proposedContent?.envelope).toEqual(
            JSON.stringify(envelopeToJSON(sigBundle.dsseEnvelope))
          );
          expect(entry.spec.proposedContent?.verifiers).toHaveLength(1);
          expect(entry.spec.proposedContent?.verifiers[0]).toEqual(
            enc.base64Encode(publicKey)
          );
        });
      });
    });
  });

  describe('when a DSSE envelope is provided', () => {
    describe('when the keyid is a non-empty string', () => {
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
        expect(e).toEqual(
          JSON.stringify(envelopeToJSON(sigBundle.dsseEnvelope))
        );

        expect(entry.spec.proposedContent?.verifiers).toHaveLength(1);
        expect(entry.spec.proposedContent?.verifiers[0]).toEqual(
          enc.base64Encode(publicKey)
        );
      });
    });
  });
});
