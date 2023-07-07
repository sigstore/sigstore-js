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
import { HashAlgorithm, Bundle as ProtoBundle } from '@sigstore/protobuf-specs';
import { fromPartial } from '@total-typescript/shoehorn';
import {
  Bundle,
  BundleLatest,
  BundleV01,
  isBundleWithCertificateChain,
  isBundleWithDsseEnvelope,
  isBundleWithMessageSignature,
  isBundleWithPublicKey,
} from '../bundle';

describe('BundleV01', () => {
  const bundle = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: {
          certificates: [{ rawBytes: Buffer.from('') }],
        },
      },
      timestampVerificationData: {
        rfc3161Timestamps: [{ signedTimestamp: Buffer.from('') }],
      },
      tlogEntries: [
        {
          logIndex: '123',
          logId: { keyId: Buffer.from('') },
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
        messageDigest: {
          algorithm: HashAlgorithm.SHA2_256,
          digest: Buffer.from(''),
        },
        signature: Buffer.from(''),
      },
    },
  } satisfies ProtoBundle;

  it('is assignable from a properly formed bundle', () => {
    const v01Bundle: BundleV01 = bundle;
    expect(v01Bundle).toBeDefined();
  });
});

describe('BundleLatest', () => {
  const bundle = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
    verificationMaterial: {
      content: {
        $case: 'publicKey',
        publicKey: { hint: '' },
      },
      timestampVerificationData: {
        rfc3161Timestamps: [{ signedTimestamp: Buffer.from('') }],
      },
      tlogEntries: [
        {
          logIndex: '123',
          logId: { keyId: Buffer.from('') },
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
        payloadType: 'text/plain',
        payload: Buffer.from(''),
        signatures: [{ keyid: '', sig: Buffer.from('') }],
      },
    },
  } satisfies ProtoBundle;

  it('is assignable from a properly formed bundle', () => {
    const vLatestBundle: BundleLatest = bundle;
    expect(vLatestBundle).toBeDefined();
  });
});

describe('isBundleWithCertificateChain', () => {
  describe('when the bundle has a certificate chain', () => {
    const bundle: Bundle = fromPartial({
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('') }],
          },
        },
      },
    });

    it('returns true', () => {
      expect(isBundleWithCertificateChain(bundle)).toBe(true);
    });
  });

  describe('when the bundle does not have a certificate chain', () => {
    const bundle: Bundle = fromPartial({
      verificationMaterial: {
        content: {
          $case: 'publicKey',
          publicKey: { hint: '' },
        },
      },
    });

    it('returns false', () => {
      expect(isBundleWithCertificateChain(bundle)).toBe(false);
    });
  });
});

describe('isBundleWithPublicKey', () => {
  describe('when the bundle has a public key', () => {
    const bundle: Bundle = fromPartial({
      verificationMaterial: {
        content: {
          $case: 'publicKey',
          publicKey: { hint: '' },
        },
      },
    });

    it('returns true', () => {
      expect(isBundleWithPublicKey(bundle)).toBe(true);
    });
  });

  describe('when the bundle does NOT have a public key', () => {
    const bundle: Bundle = fromPartial({
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('') }],
          },
        },
      },
    });

    it('returns false', () => {
      expect(isBundleWithPublicKey(bundle)).toBe(false);
    });
  });
});

describe('isBundleWithMessageSignature', () => {
  describe('when the bundle has a message signature', () => {
    const bundle: Bundle = fromPartial({
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: {
            algorithm: HashAlgorithm.SHA2_256,
            digest: Buffer.from(''),
          },
          signature: Buffer.from(''),
        },
      },
    });

    it('returns true', () => {
      expect(isBundleWithMessageSignature(bundle)).toBe(true);
    });
  });

  describe('when the bundle does NOT have a message signature', () => {
    const bundle: Bundle = fromPartial({
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payloadType: 'text/plain',
          payload: Buffer.from(''),
          signatures: [{ keyid: '', sig: Buffer.from('') }],
        },
      },
    });

    it('returns false', () => {
      expect(isBundleWithMessageSignature(bundle)).toBe(false);
    });
  });
});

describe('isBundleWithDSSEnvelope', () => {
  describe('when the bundle has a DSSEnvelope', () => {
    const bundle: Bundle = fromPartial({
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payloadType: 'text/plain',
          payload: Buffer.from(''),
          signatures: [{ keyid: '', sig: Buffer.from('') }],
        },
      },
    });

    it('returns true', () => {
      expect(isBundleWithDsseEnvelope(bundle)).toBe(true);
    });
  });

  describe('when the bundle does NOT have a DSSEnvelope', () => {
    const bundle: Bundle = fromPartial({
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: {
            algorithm: HashAlgorithm.SHA2_256,
            digest: Buffer.from(''),
          },
          signature: Buffer.from(''),
        },
      },
    });

    it('returns false', () => {
      expect(isBundleWithDsseEnvelope(bundle)).toBe(false);
    });
  });
});
