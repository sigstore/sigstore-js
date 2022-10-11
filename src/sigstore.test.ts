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
import { Bundle, HashAlgorithm } from './types/bundle';
import { Verifier } from './verify';

jest.mock('./sign');

describe('sign', () => {
  const payload = Buffer.from('Hello, world!');

  // Signer output
  const signedPayload: Bundle = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
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
    timestampVerificationData: {
      rfc3161Timestamps: [],
      tlogEntries: [],
    },
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: {
          certificates: [],
        },
      },
    },
  };

  const mockSigner = jest.mocked(Signer);
  const mockSign = jest.fn();

  beforeEach(() => {
    mockSigner.mockClear();

    mockSign.mockClear();
    mockSign.mockResolvedValueOnce(signedPayload);
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
    expect(options).toHaveProperty('rekor', expect.anything());
    expect(options.identityProviders).toHaveLength(1);
  });

  it('invokes the Signer instance with the correct params', async () => {
    await sign(payload);

    expect(mockSign).toHaveBeenCalledWith(payload);
  });

  it('returns the correct envelope', async () => {
    const sig = await sign(payload);
    expect(sig).toMatchSnapshot();
  });
});

describe('signAttestation', () => {
  const payload = Buffer.from('Hello, world!');
  const payloadType = 'text/plain';

  // Signer output
  const signedPayload = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
    content: {
      $case: 'dsseEnvelope',
      dsseEnvelope: {
        payload: Buffer.from(''),
        payloadType: 'text/json',
        signatures: [
          {
            sig: Buffer.from(''),
            keyid: 'key-123',
          },
        ],
      },
    },
    timestampVerificationData: {
      rfc3161Timestamps: [],
      tlogEntries: [],
    },
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: {
          certificates: [],
        },
      },
    },
  };

  const mockSigner = jest.mocked(Signer);
  const mockSign = jest.fn();

  beforeEach(() => {
    mockSigner.mockClear();

    mockSign.mockClear();
    mockSign.mockResolvedValueOnce(signedPayload);
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
    expect(options).toHaveProperty('rekor', expect.anything());
    expect(options.identityProviders).toHaveLength(1);
  });

  it('invokes the Signer instance with the correct params', async () => {
    await signAttestation(payload, payloadType);

    expect(mockSign).toHaveBeenCalledWith(payload, payloadType);
  });

  it('returns the correct envelope', async () => {
    const sig = await signAttestation(payload, payloadType);
    expect(sig).toMatchSnapshot();
  });
});

describe('#verify', () => {
  const bundle: Bundle = {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
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
    timestampVerificationData: {
      rfc3161Timestamps: [],
      tlogEntries: [],
    },
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: {
          certificates: [],
        },
      },
    },
  };
  const bundleJson = JSON.stringify(Bundle.toJSON(bundle));

  const mockVerify = jest.fn();

  beforeEach(() => {
    mockVerify.mockClear();
    mockVerify.mockResolvedValueOnce(false);
    jest.spyOn(Verifier.prototype, 'verify').mockImplementation(mockVerify);
  });

  it('invokes the Verifier instance with the correct params', async () => {
    await verify(bundleJson);
    expect(mockVerify).toHaveBeenCalledWith(bundle, undefined);
  });

  it('returns the value returned by the verifier', async () => {
    const result = await verify(bundleJson);
    expect(result).toBe(false);
  });
});
