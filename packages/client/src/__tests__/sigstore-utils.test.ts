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
import { envelopeToJSON } from '@sigstore/bundle';
import { mockRekor } from '@sigstore/mock';
import { createDSSEEnvelope, createRekorEntry } from '../sigstore-utils';
import { dsse } from '../util';

const payload = Buffer.from('Hello, world!');
const payloadType = 'text/plain';
const sigMaterial = {
  key: {
    id: 'sha256-1234',
    value: 'key',
  },
  signature: Buffer.from('abc'),
};

describe('createDSSEEnvelope', () => {
  const mockSign = jest.fn();
  const options = {
    signer: mockSign,
  };

  beforeEach(() => {
    mockSign.mockClear();
    mockSign.mockResolvedValueOnce(sigMaterial);
  });

  it('calls the signer with the correct payload', async () => {
    await createDSSEEnvelope(payload, payloadType, options);

    // Signer func was called
    expect(mockSign).toHaveBeenCalledTimes(1);
    const args = mockSign.mock.calls[0];

    expect(args).toHaveLength(1);
    const signerArg = args[0];

    // Signer was constructed with the correct options
    expect(signerArg).toEqual(dsse.preAuthEncoding(payloadType, payload));
  });

  it('returns a serialized envelope', async () => {
    const envelope = await createDSSEEnvelope(payload, payloadType, options);

    expect(envelope).toEqual({
      payloadType: 'text/plain',
      payload: 'SGVsbG8sIHdvcmxkIQ==',
      signatures: [
        {
          keyid: 'sha256-1234',
          sig: 'YWJj',
        },
      ],
    });
  });
});

describe('createRekorEntry', () => {
  const rekorURL = 'https://rekor.example.com';

  const envelope = envelopeToJSON({
    payloadType,
    payload,
    signatures: [
      {
        keyid: 'sha256-1234',
        sig: Buffer.from('deadbeef', 'hex'),
      },
    ],
  });

  beforeEach(async () => {
    await mockRekor({ baseURL: rekorURL });
  });

  it('returns a bundle', async () => {
    const bundle = await createRekorEntry(envelope, 'foo', { rekorURL });

    expect(bundle).toBeDefined();
    expect(bundle.dsseEnvelope?.payloadType).toBe(payloadType);
    expect(bundle.dsseEnvelope?.payload).toBe(payload.toString('base64'));
    expect(bundle.dsseEnvelope?.signatures).toHaveLength(1);

    expect(bundle.verificationMaterial.publicKey?.hint).toBe('sha256-1234');

    expect(bundle.verificationMaterial.tlogEntries).toHaveLength(1);
    expect(bundle.verificationMaterial.tlogEntries[0].kindVersion?.kind).toBe(
      'intoto'
    );

    expect(
      bundle.verificationMaterial.timestampVerificationData?.rfc3161Timestamps
    ).toHaveLength(0);
  });
});
