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
import { PolicyError, VerificationError } from '../error';
import { Signer } from '../sign';
import { attest, sign, utils, verify, VerifyOptions } from '../sigstore';
import { getTrustedRoot } from '../tuf';
import {
  Bundle,
  HashAlgorithm,
  TimestampVerificationData,
  TransparencyLogEntry,
  X509CertificateChain,
} from '../types/sigstore';
import bundles from './__fixtures__/bundles';
import { trustedRoot } from './__fixtures__/trust';

jest.mock('../sign');
jest.mock('../tuf');

const tlogEntries: TransparencyLogEntry[] = [
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
];

const timestampVerificationData: TimestampVerificationData = {
  rfc3161Timestamps: [{ signedTimestamp: Buffer.from('signedTimestamp') }],
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
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: x509CertificateChain,
      },
      tlogEntries,
      timestampVerificationData,
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
    verificationMaterial: {
      content: {
        $case: 'x509CertificateChain',
        x509CertificateChain: x509CertificateChain,
      },
      tlogEntries,
      timestampVerificationData,
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
    await attest(payload, payloadType);

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
    await attest(payload, payloadType);

    expect(mockSign).toHaveBeenCalledWith(payload, payloadType);
  });

  it('returns the correct envelope', async () => {
    const sig = await attest(payload, payloadType);

    expect(sig).toEqual(Bundle.toJSON(bundle));
  });
});

describe('#verify', () => {
  // Mock the getTrustedRoot function so that we don't have to interact
  // with the real Sigstore TUF repo
  jest.mocked(getTrustedRoot).mockResolvedValue(trustedRoot);

  describe('when everything in the bundle is valid', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, {})).resolves.toBe(undefined);
    });
  });

  describe('when there is a signature mismatch', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = Buffer.from('');
    it('throws an error', async () => {
      await expect(verify(bundle, artifact, {})).rejects.toThrowError(
        VerificationError
      );
    });
  });

  describe('when the bundle was signed by a trusted identity', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    const options: VerifyOptions = {
      certificateIssuer: 'https://github.com/login/oauth',
      certificateIdentityEmail: Buffer.from(
        'YnJpYW5AZGVoYW1lci5jb20=',
        'base64'
      ).toString('ascii'),
      certificateOIDs: {
        '1.3.6.1.4.1.57264.1.1': 'https://github.com/login/oauth',
      },
    };

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, options)).resolves.toBeUndefined();
    });
  });

  describe('when an issuer is specified w/o a SAN identity', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    const options: VerifyOptions = {
      certificateIssuer: 'https://github.com/login/oauth',
    };

    it('throws an error', async () => {
      await expect(verify(bundle, artifact, options)).rejects.toThrowError(
        PolicyError
      );
    });
  });

  describe('when the bundle was signed by an untrusted identity', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    const options: VerifyOptions = {
      certificateIssuer: 'https://github.com/login/oauth',
      certificateIdentityURI: 'https://foo.bar/',
    };

    it('throws an error', async () => {
      await expect(verify(bundle, artifact, options)).rejects.toThrowError(
        PolicyError
      );
    });
  });

  describe('when tlog timestamp is outside the validity period of the certificate', () => {
    const bundle = bundles.signature.invalid.expiredCert;
    const artifact = bundles.signature.artifact;

    it('throws an error', async () => {
      await expect(verify(bundle, artifact, {})).rejects.toThrowError(
        VerificationError
      );
    });
  });
});
