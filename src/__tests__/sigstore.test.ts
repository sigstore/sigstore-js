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
import { Signer } from '../sign';
import { sign, signAttestation, utils, verify } from '../sigstore';
import {
  Bundle,
  HashAlgorithm,
  VerificationData,
  X509CertificateChain,
} from '../types/bundle';
import bundles from './__fixtures__/bundles';

jest.mock('../sign');

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
      canonicalizedBody: Buffer.from('body'),
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
  certificates: [{ rawBytes: Buffer.from('certificate') }],
};

describe('utils', () => {
  it('exports utils', async () => {
    expect(utils.createDSSEEnvelope).toBeInstanceOf(Function);
    expect(utils.createRekorEntry).toBeInstanceOf(Function);
  });
});

describe('sign', () => {
  const payload = Buffer.from('Hello, world!');

  // Signer output
  const bundle: Bundle = {
    mediaType: 'test/output',
    verificationData: verificationData,
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: x509CertificateChain,
      },
    },
    content: {
      $case: 'messageSignature',
      messageSignature: {
        messageDigest: {
          algorithm: HashAlgorithm.SHA2_256,
          digest: Buffer.from('messageDigest'),
        },
        signature: Buffer.from('signature'),
      },
    },
  };

  const mockSigner = jest.mocked(Signer);
  const mockSign = jest.fn();

  beforeEach(() => {
    mockSigner.mockClear();

    mockSign.mockClear();
    mockSign.mockResolvedValueOnce(bundle);
    jest.spyOn(Signer.prototype, 'signBlob').mockImplementation(mockSign);
  });

  it('constructs the Signer with the correct options', async () => {
    await sign(payload);

    // Signer was constructed
    expect(mockSigner).toHaveBeenCalledTimes(1);
    const args = mockSigner.mock.calls[0];

    // Signer was constructed with options
    expect(args).toHaveLength(1);
    const options = args[0];

    // Signer was constructed with the correct options
    expect(options).toHaveProperty('ca', expect.anything());
    expect(options).toHaveProperty('tlog', expect.anything());
    expect(options.identityProviders).toHaveLength(1);
  });

  it('invokes the Signer instance with the correct params', async () => {
    await sign(payload);

    expect(mockSign).toHaveBeenCalledWith(payload);
  });

  it('returns the correct envelope', async () => {
    const sig = await sign(payload);

    expect(sig).toEqual(Bundle.toJSON(bundle));
  });
});

describe('signAttestation', () => {
  const payload = Buffer.from('Hello, world!');
  const payloadType = 'text/plain';

  // Signer output
  const bundle: Bundle = {
    mediaType: 'test/output',
    verificationData: verificationData,
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: x509CertificateChain,
      },
    },
    content: {
      $case: 'dsseEnvelope',
      dsseEnvelope: {
        payload: payload,
        payloadType: payloadType,
        signatures: [
          {
            keyid: 'keyid',
            sig: Buffer.from('signature'),
          },
        ],
      },
    },
  };

  const mockSigner = jest.mocked(Signer);
  const mockSign = jest.fn();

  beforeEach(() => {
    mockSigner.mockClear();

    mockSign.mockClear();
    mockSign.mockResolvedValueOnce(bundle);
    jest
      .spyOn(Signer.prototype, 'signAttestation')
      .mockImplementation(mockSign);
  });

  it('constructs the Signer with the correct options', async () => {
    await signAttestation(payload, payloadType);

    // Signer was constructed
    expect(mockSigner).toHaveBeenCalledTimes(1);
    const args = mockSigner.mock.calls[0];

    // Signer was constructed with options
    expect(args).toHaveLength(1);
    const options = args[0];

    // Signer was constructed with the correct options
    expect(options).toHaveProperty('ca', expect.anything());
    expect(options).toHaveProperty('tlog', expect.anything());
    expect(options.identityProviders).toHaveLength(1);
  });

  it('invokes the Signer instance with the correct params', async () => {
    await signAttestation(payload, payloadType);

    expect(mockSign).toHaveBeenCalledWith(payload, payloadType);
  });

  it('returns the correct envelope', async () => {
    const sig = await signAttestation(payload, payloadType);

    expect(sig).toEqual(Bundle.toJSON(bundle));
  });
});

describe('#verify', () => {
  describe('when everything in the bundle is valid', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact)).resolves.toBe(undefined);
    });
  });

  describe('when there is a signature mismatch', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = Buffer.from('');
    it('throws an error', async () => {
      await expect(verify(bundle, artifact)).rejects.toThrowError(
        /signature verification failed/
      );
    });
  });

  describe('when SET in bundle verification data does not match payload', () => {
    const bundle = bundles.signature.invalid.setMismatch;
    const artifact = bundles.signature.artifact;

    it('throws an error', async () => {
      await expect(verify(bundle, artifact)).rejects.toThrowError(
        /SET verification failed/
      );
    });
  });

  describe('when tlog timestamp is outside the validity period of the certificate', () => {
    const bundle = bundles.signature.invalid.expiredCert;
    const artifact = bundles.signature.artifact;

    it('throws an error', async () => {
      await expect(verify(bundle, artifact)).rejects.toThrowError(
        /integrated time is after certificate expiration/
      );
    });
  });
});
