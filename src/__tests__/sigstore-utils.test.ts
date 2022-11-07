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
import { createDSSEEnvelope } from '../sigstore-utils';
import { dsse } from '../util';

describe('createDSSEEnvelope', () => {
  const payload = Buffer.from('Hello, world!');
  const payloadType = 'text/plain';
  const sigMaterial = {
    key: {
      id: 'sha256-1234',
    },
    signature: Buffer.from('abc'),
  };

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
