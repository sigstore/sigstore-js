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
import { crypto, encoding as enc } from '../../util';
import { Envelope } from '../bundle';
import { rekor } from './index';

describe('request', () => {
  const cert = '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----';

  describe('toProposedIntotoEntry', () => {
    const envelope: Envelope = {
      payloadType: 'application/vnd.in-toto+json',
      payload: Buffer.from('payload'),
      signatures: [
        {
          keyid: '',
          sig: Buffer.from('signature'),
        },
      ],
    };

    it('returns a valid intoto entry', () => {
      const entry = rekor.toProposedIntotoEntry(envelope, cert);

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
        expect(e?.signatures[0].keyid).toEqual('');
        expect(e?.signatures[0].sig).toEqual(
          enc.base64Encode(envelope.signatures[0].sig.toString('base64'))
        );
        expect(e?.signatures[0].publicKey).toEqual(enc.base64Encode(cert));
      } else {
        fail('envelope is a string');
      }

      expect(entry.spec.content.hash).toBeTruthy();
      expect(entry.spec.content.hash?.algorithm).toBe('sha256');
      expect(entry.spec.content.hash?.value).toBe(
        crypto.hash(JSON.stringify(envelope.payload)).toString('hex')
      );
    });
  });

  describe('toProposedHashedRekordEntry', () => {
    const digest = Buffer.from('digest');
    const signature = Buffer.from('signature');

    it('returns a valid hashedrekord entry', () => {
      const entry = rekor.toProposedHashedRekordEntry(digest, signature, cert);

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
});
