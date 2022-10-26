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
import { Signer } from './sign';
import { sign, signAttestation, verify } from './sigstore';
import {
  Bundle,
  HashAlgorithm,
  SerializedBundle,
  VerificationData,
  X509CertificateChain,
} from './types/bundle';
import { Verifier } from './verify';

jest.mock('./sign');

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
    expect(options).toHaveProperty('fulcio', expect.anything());
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
    expect(options).toHaveProperty('fulcio', expect.anything());
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
  const bundle: SerializedBundle = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
    dsseEnvelope: undefined,
    messageSignature: {
      messageDigest: {
        algorithm: 'SHA2_256',
        digest: '1o51L/K0DEbwMF440I3k26pgNTMNwppInpR+aU+a0Hw=',
      },
      signature:
        'MEUCIEBnPQyP/nzkuBZcdX6faw8TpDGkxMJ+EiCgy4IrZ0kHAiEA8j+nFFNiI5JN36yNynao6uLw0Z5DE99Gi+mnP7QV+Uk=',
    },
    verificationData: {
      timestampVerificationData: {
        rfc3161Timestamps: [],
      },
      tlogEntries: [],
    },
    verificationMaterial: {
      publicKey: undefined,
      x509CertificateChain: {
        certificates: [{ derBytes: '' }],
      },
    },
  };

  const mockVerify = jest.fn();

  beforeEach(() => {
    mockVerify.mockClear();
    mockVerify.mockResolvedValueOnce(false);
    jest.spyOn(Verifier.prototype, 'verify').mockImplementation(mockVerify);
  });

  it('invokes the Verifier instance with the correct params', async () => {
    await verify(bundle);
    expect(mockVerify).toHaveBeenCalledWith(Bundle.fromJSON(bundle), undefined);
  });

  it('returns the value returned by the verifier', async () => {
    const result = await verify(bundle);
    expect(result).toBe(false);
  });
});
