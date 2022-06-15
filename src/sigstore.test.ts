import { Verifier } from './verify';
import { Signer } from './sign';
import { Sigstore } from './sigstore';
import { pae } from './dsse';
import identity from './identity';

jest.mock('./sign');

describe('Sigstore', () => {
  const subject = new Sigstore();

  describe('#sign', () => {
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

      await subject.sign(payload);

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
      expect(options.identityProviders[0]).toBe(identity.ciContextProvider);
    });

    it('invokes the Signer instance with the correct params', async () => {
      await subject.sign(payload);

      expect(mockSign).toHaveBeenCalledWith(payload);
    });

    it('returns the correct envelope', async () => {
      const sig = await subject.sign(payload);

      expect(sig).toEqual(signedPayload);
    });
  });

  describe('#signDSSE', () => {
    const payload = Buffer.from('Hello, world!');
    const payloadType = 'test/plain';

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

    it('invokes the Signer instance with the correct params', async () => {
      await subject.signDSSE(payload, payloadType);

      const paeBuffer = pae(payloadType, payload);
      expect(mockSign).toHaveBeenCalledWith(paeBuffer);
    });

    it('returns the correct envelope', async () => {
      const envelope = await subject.signDSSE(payload, payloadType);

      expect(envelope).toEqual({
        payload: payload.toString('base64'),
        payloadType: payloadType,
        signatures: [{ keyid: '', sig: signedPayload.base64Signature }],
      });
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
      await subject.verify(payload, signature);

      expect(mockVerify).toHaveBeenCalledWith(payload, signature);
    });

    it('returns the value returned by the verifier', async () => {
      const result = await subject.verify(payload, signature);
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
      mockVerify.mockResolvedValueOnce(true);
      jest.spyOn(Verifier.prototype, 'verify').mockImplementation(mockVerify);
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
