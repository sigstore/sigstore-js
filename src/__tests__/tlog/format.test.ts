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
import {
  toProposedHashedRekordEntry,
  toProposedIntotoEntry,
} from '../../tlog/format';
import { SignatureMaterial } from '../../types/signature';
import { Envelope } from '../../types/sigstore';
import { crypto, encoding as enc } from '../../util';

describe('format', () => {
  const cert = '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----';
  const signature = Buffer.from('signature');
  const sigMaterial: SignatureMaterial = {
    signature: signature,
    certificates: [cert],
    key: undefined,
  };

  describe('toProposedHashedRekordEntry', () => {
    const digest = Buffer.from('digest');
    const signature = Buffer.from('signature');

    it('returns a valid hashedrekord entry', () => {
      const entry = toProposedHashedRekordEntry(digest, sigMaterial);

      expect(entry.apiVersion).toEqual('0.0.1');
      expect(entry.kind).toEqual('hashedrekord');
      expect(entry.spec).toBeTruthy();

      expect(entry.spec.data).toBeTruthy();
      expect(entry.spec.data.hash).toBeTruthy();
      expect(entry.spec.data.hash?.algorithm).toBe('sha256');
      expect(entry.spec.data.hash?.value).toBe(digest.toString('hex'));

      expect(entry.spec.signature).toBeTruthy();
      expect(entry.spec.signature?.content).toBe(signature.toString('base64'));
      expect(entry.spec.signature?.publicKey).toBeTruthy();
      expect(entry.spec.signature?.publicKey?.content).toBe(
        enc.base64Encode(cert)
      );
    });
  });

  describe('toProposedIntotoEntry', () => {
    describe('when the keyid is a non-empty string', () => {
      const envelope: Envelope = {
        payloadType: 'application/vnd.in-toto+json',
        payload: Buffer.from('payload'),
        signatures: [{ keyid: '123', sig: signature }],
      };

      it('returns a valid intoto entry', () => {
        const entry = toProposedIntotoEntry(envelope, sigMaterial);

        expect(entry.apiVersion).toEqual('0.0.2');
        expect(entry.kind).toEqual('intoto');
        expect(entry.spec).toBeTruthy();
        expect(entry.spec.content).toBeTruthy();
        expect(entry.spec.content.envelope).toBeTruthy();

        if (typeof entry.spec.content.envelope !== 'string') {
          const e = entry.spec.content.envelope;
          expect(e?.payloadType).toEqual(envelope.payloadType);
          expect(e?.payload).toEqual(
            enc.base64Encode(envelope.payload.toString('base64'))
          );
          expect(e?.signatures).toHaveLength(1);
          expect(e?.signatures[0].keyid).toEqual(envelope.signatures[0].keyid);
          expect(e?.signatures[0].sig).toEqual(
            enc.base64Encode(envelope.signatures[0].sig.toString('base64'))
          );
          expect(e?.signatures[0].publicKey).toEqual(enc.base64Encode(cert));
        } else {
          fail('intoto type is v0.0.1 but expecting v0.0.2');
        }

        expect(entry.spec.content.payloadHash).toBeTruthy();
        expect(entry.spec.content.payloadHash?.algorithm).toBe('sha256');
        expect(entry.spec.content.payloadHash?.value).toBe(
          crypto.hash(envelope.payload).toString('hex')
        );
        expect(entry.spec.content.hash).toBeTruthy();
        expect(entry.spec.content.hash?.algorithm).toBe('sha256');

        // This hard-coded hash value helps us detect if we've unintentionally
        // changed the hashing algorithm.
        expect(entry.spec.content.hash?.value).toBe(
          '91a5eb7452452720d704da5442acb9703252b3ab7be51ec155a244f5c9aa5ec8'
        );
      });
    });

    describe('when the keyid is an empty string', () => {
      const envelope: Envelope = {
        payloadType: 'application/vnd.in-toto+json',
        payload: Buffer.from('payload'),
        signatures: [{ keyid: '', sig: signature }],
      };

      it('returns a valid intoto entry', () => {
        const entry = toProposedIntotoEntry(envelope, sigMaterial);

        if (typeof entry.spec.content.envelope === 'string') {
          fail('intoto type is v0.0.1 but expecting v0.0.2');
        }

        // Ensure the keyid is not included in the envelope.
        const e = entry.spec.content.envelope;
        expect(e?.signatures).toHaveLength(1);
        expect(e?.signatures[0].keyid).toBeUndefined();
        expect(e?.signatures[0].sig).toEqual(
          enc.base64Encode(envelope.signatures[0].sig.toString('base64'))
        );

        // This hard-coded hash value helps us detect if we've unintentionally
        // changed the hashing algorithm.
        expect(entry.spec.content.hash?.value).toBe(
          '295fd391f3b3f349cdaa686befaa765d90c0b411a0811e45f8bc481338a51622'
        );
      });
    });

    describe('when there are multiple signatures in the envelope', () => {
      const envelope: Envelope = {
        payloadType: 'application/vnd.in-toto+json',
        payload: Buffer.from('payload'),
        signatures: [
          { keyid: '123', sig: signature },
          { keyid: '', sig: signature },
        ],
      };

      it('returns a valid intoto entry', () => {
        const entry = toProposedIntotoEntry(envelope, sigMaterial);

        if (typeof entry.spec.content.envelope === 'string') {
          fail('intoto type is v0.0.1 but expecting v0.0.2');
        }

        // Check to ensure only the first signature is included in the envelope
        const e = entry.spec.content.envelope;
        expect(e?.signatures).toHaveLength(1);
        expect(e?.signatures[0].keyid).toEqual(envelope.signatures[0].keyid);
        expect(e?.signatures[0].sig).toEqual(
          enc.base64Encode(envelope.signatures[0].sig.toString('base64'))
        );
        expect(e?.signatures[0].publicKey).toEqual(enc.base64Encode(cert));

        // This hard-coded hash value helps us detect if we've unintentionally
        // changed the hashing algorithm.
        expect(entry.spec.content.hash?.value).toBe(
          '91a5eb7452452720d704da5442acb9703252b3ab7be51ec155a244f5c9aa5ec8'
        );
      });
    });
  });
});
