import { Verifier } from './verify';
import { Signer } from './sign';
import { Sigstore } from './sigstore';
import { pae } from './dsse';

// Mock Signer and Verifier classes
jest.mock('./sign');
jest.mock('./verify');

describe('Sigstore', () => {
  let subject: Sigstore;
  const MockedVerifier = jest.mocked(Verifier, true);
  const MockedSigner = jest.mocked(Signer, true);

  beforeEach(() => {
    MockedVerifier.mockClear();
    MockedSigner.mockClear();

    // Subject must be instantiated AFTER the mocks are cleared
    subject = new Sigstore({});
  });

  describe('#signRaw', () => {
    const payload = Buffer.from('Hello, world!');
    const jwt = 'a.b.c';

    // Signer output
    const signedPayload = {
      base64Signature: 'signature',
      cert: 'cert',
    };

    const mockSign = jest.fn();

    beforeEach(() => {
      mockSign.mockClear();
      MockedSigner.mock.instances[0].sign =
        mockSign.mockResolvedValueOnce(signedPayload);
    });

    it('invokes the Signer instance with the correct params', async () => {
      await subject.signRaw(payload, jwt);

      expect(mockSign).toHaveBeenCalledWith(payload, jwt);
    });

    it('returns the correct envelope', async () => {
      const sig = await subject.signRaw(payload, jwt);

      expect(sig).toEqual(signedPayload);
    });
  });

  describe('#signDSSE', () => {
    const payload = Buffer.from('Hello, world!');
    const payloadType = 'test/plain';
    const jwt = 'a.b.c';

    // Signer output
    const signedPayload = {
      base64Signature: 'signature',
      cert: 'cert',
    };

    const mockSign = jest.fn();

    beforeEach(() => {
      mockSign.mockClear();
      MockedSigner.mock.instances[0].sign =
        mockSign.mockResolvedValueOnce(signedPayload);
    });

    it('invokes the Signer instance with the correct params', async () => {
      await subject.signDSSE(payload, payloadType, jwt);

      const paeBuffer = pae(payloadType, payload);
      expect(mockSign).toHaveBeenCalledWith(paeBuffer, jwt);
    });

    it('returns the correct envelope', async () => {
      const envelope = await subject.signDSSE(payload, payloadType, jwt);

      expect(envelope).toEqual({
        payload: payload.toString('base64'),
        payloadType: payloadType,
        signatures: [{ keyid: '', sig: signedPayload.base64Signature }],
      });
    });
  });

  describe('#verifyOnline', () => {
    const payload = Buffer.from('Hello, world!');
    const signature = 'a1b2c3';

    const mockVerify = jest.fn();

    beforeEach(() => {
      mockVerify.mockClear();
      MockedVerifier.mock.instances[0].verify =
        mockVerify.mockResolvedValueOnce(false);
    });

    it('invokes the Verifier instance with the correct params', async () => {
      await subject.verifyOnline(payload, signature);

      expect(mockVerify).toHaveBeenCalledWith(payload, signature);
    });

    it('returns the value returned by the verifier', async () => {
      const result = await subject.verifyOnline(payload, signature);
      expect(result).toBe(false);
    });
  });

  describe('#verifyDSSE', () => {
    const envelope = {
      payloadType: 'text/plain',
      payload: 'SGVsbG8sIFdvcmxkIQ==',
      signatures: [{ keyid: '', sig: 'a1b2c3' }],
    };

    const mockVerify = jest.fn();

    beforeEach(() => {
      mockVerify.mockClear();
      MockedVerifier.mock.instances[0].verify =
        mockVerify.mockResolvedValueOnce(true);
    });

    it('invokes the Verifier instance with the correct params', async () => {
      await subject.verifyDSSE(envelope);

      // Calcualte the payload we expect to be passed to the verifier
      const payload = Buffer.from(envelope.payload, 'base64');
      const paeBuffer = pae(envelope.payloadType, payload);

      expect(mockVerify).toHaveBeenCalledWith(
        paeBuffer,
        envelope.signatures[0].sig
      );
    });

    it('returns the value returned by the verifier', async () => {
      const result = await subject.verifyDSSE(envelope);
      expect(result).toBe(true);
    });
  });
});
