import assert from 'assert';
import { EphemeralSigner } from '../../signatory/ephemeral';

describe('EphemeralSigner', () => {
  describe('constructor', () => {
    it('should create a new instance', () => {
      const client = new EphemeralSigner();
      expect(client).toBeDefined();
    });
  });

  describe('sign', () => {
    const subject = new EphemeralSigner();
    const message = Buffer.from('message');

    it('returns the signature', async () => {
      const endorsement = await subject.sign(message);
      expect(endorsement).toBeDefined();
      expect(endorsement.signature).toBeDefined();
      expect(endorsement.key.$case).toEqual('publicKey');
      assert(endorsement.key.$case === 'publicKey');
      expect(endorsement.key.publicKey).toBeDefined();
    });
  });
});
