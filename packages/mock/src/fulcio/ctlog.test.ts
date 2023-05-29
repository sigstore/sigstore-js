import crypto from 'crypto';
import { CTLog, initializeCTLog } from './ctlog';

describe('CTLog', () => {
  describe('initializeCTLog', () => {
    it('returns a CTLog', async () => {
      const ctLog: CTLog = await initializeCTLog();
      expect(ctLog).toBeDefined();
    });
  });

  describe('#publicKey', () => {
    it('returns a key', async () => {
      const ctLog: CTLog = await initializeCTLog();
      expect(ctLog.publicKey).toBeDefined();
    });
  });

  describe('#logID', () => {
    it('returns the log ID', async () => {
      const ctLog: CTLog = await initializeCTLog();
      expect(ctLog.logID.toString('hex')).toMatch(/^[0-9a-f]{64}$/);
    });

    it('returns the log ID matching the public key', async () => {
      const ctLog: CTLog = await initializeCTLog();

      const logID = ctLog.logID.toString('hex');
      const keyDigest = crypto
        .createHash('sha256')
        .update(ctLog.publicKey)
        .digest('hex');
      expect(logID).toMatch(keyDigest);
    });
  });
});
