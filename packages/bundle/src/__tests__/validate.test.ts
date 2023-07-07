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
import { fromPartial } from '@total-typescript/shoehorn';
import assert from 'assert';
import { ValidationError } from '../error';
import {
  assertBundle,
  assertBundleLatest,
  assertBundleV01,
  isBundleV01,
} from '../validate';

import type { Bundle as ProtoBundle } from '@sigstore/protobuf-specs';
import type { Bundle } from '../bundle';

describe('assertBundle', () => {
  describe('when the bundle is completely empty', () => {
    const bundle: ProtoBundle = fromPartial({});

    it('throws an error', () => {
      expect.assertions(4);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(3);
        expect(e.fields).toContain('mediaType');
        expect(e.fields).toContain('content');
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when the mediaType is incorrect', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'FOO',
    });

    it('throws an error', () => {
      expect.assertions(4);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(3);
        expect(e.fields).toContain('mediaType');
        expect(e.fields).toContain('content');
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when the messageDigest is undefined for messageSignature', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'messageSignature',
        messageSignature: {
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(3);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(2);
        expect(e.fields).toContain('content.messageSignature.messageDigest');
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when the messageDigest is empty for messageSignature', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.alloc(0) },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(3);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(2);
        expect(e.fields).toContain(
          'content.messageSignature.messageDigest.digest'
        );
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when the signature is empty for messageSignature', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.alloc(0),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(3);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(2);
        expect(e.fields).toContain('content.messageSignature.signature');
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when the payload is undefined for dsseEnvelope', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payload: Buffer.alloc(0),
          payloadType: 'application/json',
          signatures: [{ sig: Buffer.from('ABC'), keyid: '' }],
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(3);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(2);
        expect(e.fields).toContain('content.dsseEnvelope.payload');
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when there are too few signatures for dsseEnvelope', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payload: Buffer.from('ABC'),
          payloadType: 'application/json',
          signatures: [],
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(3);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(2);
        expect(e.fields).toContain('content.dsseEnvelope.signatures');
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when there are too many signatures for dsseEnvelope', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payload: Buffer.from('ABC'),
          payloadType: 'application/json',
          signatures: [
            { sig: Buffer.from('ABC'), keyid: '' },
            { sig: Buffer.from('ABC'), keyid: '' },
          ],
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(3);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(2);
        expect(e.fields).toContain('content.dsseEnvelope.signatures');
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when the signature value is undefined for dsseEnvelope', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payload: Buffer.from('ABC'),
          payloadType: 'application/json',
          signatures: [{ sig: Buffer.alloc(0), keyid: '' }],
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(3);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(2);
        expect(e.fields).toContain('content.dsseEnvelope.signatures[0].sig');
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when the verificationMaterial is undefined', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain('verificationMaterial');
      }
    });
  });

  describe('when the verificationMaterial content is undefined', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        tlogEntries: [],
        timestampVerificationData: undefined,
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain('verificationMaterial.content');
      }
    });
  });

  describe('when the certificate chain is empty for x509CertificateChain', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [],
          },
        },
        tlogEntries: [],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain(
          'verificationMaterial.content.x509CertificateChain.certificates'
        );
      }
    });
  });

  describe('when the certificate chain is missing a certificate for x509CertificateChain', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.alloc(0) }],
          },
        },
        tlogEntries: [],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain(
          'verificationMaterial.content.x509CertificateChain.certificates[0].rawBytes'
        );
      }
    });
  });

  describe('when the tlogEntries is undefined', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain('verificationMaterial.tlogEntries');
      }
    });
  });

  describe('when the tlogEntry is missing the logId', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: { signedEntryTimestamp: Buffer.from('') },
            inclusionProof: undefined,
          },
        ],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain('verificationMaterial.tlogEntries[0].logId');
      }
    });
  });

  describe('when the tlogEntry is missing the kindVersion', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: { signedEntryTimestamp: Buffer.from('') },
            inclusionProof: undefined,
          },
        ],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundle(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain(
          'verificationMaterial.tlogEntries[0].kindVersion'
        );
      }
    });
  });

  describe('when everything is valid', () => {
    const bundle: ProtoBundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: { signedEntryTimestamp: Buffer.from('') },
            inclusionProof: undefined,
          },
        ],
      },
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payload: Buffer.from('ABC'),
          payloadType: 'application/json',
          signatures: [{ sig: Buffer.from('BAR'), keyid: '' }],
        },
      },
    });

    it('does NOT throw an error', () => {
      expect(() => assertBundle(bundle)).not.toThrow();
    });
  });
});

describe('assertBundleV01', () => {
  describe('when the mediaType is incorrect', () => {
    const bundle: Bundle = fromPartial({
      mediaType: 'FOO',
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundleV01(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain('mediaType');
      }
    });
  });

  describe('when the tlogEntry is missing the inclusionPromise', () => {
    const bundle: Bundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionProof: undefined,
          },
        ],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundleV01(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain(
          'verificationMaterial.tlogEntries[0].inclusionPromise'
        );
      }
    });
  });

  describe('when everything is valid', () => {
    const bundle: Bundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: { signedEntryTimestamp: Buffer.from('') },
            inclusionProof: undefined,
          },
        ],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect(() => assertBundleV01(bundle)).not.toThrow();
    });
  });
});

describe('assertBundleLatest', () => {
  describe('when the tlogEntry is missing the inclusionProof', () => {
    const bundle: Bundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: undefined,
          },
        ],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundleLatest(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain(
          'verificationMaterial.tlogEntries[0].inclusionProof'
        );
      }
    });
  });

  describe('when the inclusionProof is missing the checkpoint', () => {
    const bundle: Bundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: undefined,
            inclusionProof: {
              logIndex: '123',
              treeSize: '123',
              rootHash: Buffer.from(''),
              hashes: [Buffer.from('')],
            },
          },
        ],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('throws an error', () => {
      expect.assertions(2);
      try {
        assertBundleLatest(bundle);
      } catch (e) {
        assert(e instanceof ValidationError);
        expect(e.fields).toHaveLength(1);
        expect(e.fields).toContain(
          'verificationMaterial.tlogEntries[0].inclusionProof.checkpoint'
        );
      }
    });
  });

  describe('when everything is valid', () => {
    const bundle: Bundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: undefined,
            inclusionProof: {
              checkpoint: { envelope: '' },
              logIndex: '123',
              treeSize: '123',
              rootHash: Buffer.from(''),
              hashes: [Buffer.from('')],
            },
          },
        ],
      },
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payload: Buffer.from('ABC'),
          payloadType: 'application/json',
          signatures: [{ sig: Buffer.from('BAR'), keyid: '' }],
        },
      },
    });

    it('does NOT throw an error', () => {
      expect(() => assertBundleLatest(bundle)).not.toThrow();
    });
  });
});

describe('isBundleV01', () => {
  describe('when the bundle is a v0.1 bundle', () => {
    const bundle: Bundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: { signedEntryTimestamp: Buffer.from('') },
            inclusionProof: undefined,
          },
        ],
      },
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    });

    it('returns true', () => {
      expect(isBundleV01(bundle)).toBe(true);
    });
  });

  describe('when the bundle is a v0.2 bundle', () => {
    const bundle: Bundle = fromPartial({
      mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
        tlogEntries: [
          {
            logIndex: '123',
            logId: { keyId: Buffer.from('123') },
            kindVersion: { kind: 'intoto', version: '0.1.0' },
            canonicalizedBody: Buffer.from(''),
            integratedTime: '0',
            inclusionPromise: undefined,
            inclusionProof: {
              checkpoint: { envelope: '' },
              logIndex: '123',
              treeSize: '123',
              rootHash: Buffer.from(''),
              hashes: [Buffer.from('')],
            },
          },
        ],
      },
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payload: Buffer.from('ABC'),
          payloadType: 'application/json',
          signatures: [{ sig: Buffer.from('BAR'), keyid: '' }],
        },
      },
    });

    it('returns true', () => {
      expect(isBundleV01(bundle)).toBe(false);
    });
  });
});
