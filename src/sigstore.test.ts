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
import { Verifier } from './verify';
import { Signer } from './sign';
import { sign, verify } from './sigstore';

jest.mock('./sign');

describe('sign', () => {
  const payload = Buffer.from('Hello, world!');

  // Signer output
  const signedPayload = {
    base64Signature: 'signature',
    cert: 'cert',
  };

  const mockSign = jest.fn();

  beforeEach(() => {
    mockSign.mockClear();
    mockSign.mockResolvedValueOnce(signedPayload);
    jest.spyOn(Signer.prototype, 'sign').mockImplementation(mockSign);
  });

  it('constructs the Signer with the correct options', async () => {
    const mockSigner = jest.mocked(Signer);

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

    expect(sig).toEqual(signedPayload);
  });
});

describe('#verify', () => {
  const payload = Buffer.from('Hello, world!');
  const signature = 'a1b2c3';

  const mockVerify = jest.fn();

  beforeEach(() => {
    mockVerify.mockClear();
    mockVerify.mockResolvedValueOnce(false);
    jest.spyOn(Verifier.prototype, 'verify').mockImplementation(mockVerify);
  });

  it('invokes the Verifier instance with the correct params', async () => {
    await verify(payload, signature);

    expect(mockVerify).toHaveBeenCalledWith(payload, signature);
  });

  it('returns the value returned by the verifier', async () => {
    const result = await verify(payload, signature);
    expect(result).toBe(false);
  });
});
