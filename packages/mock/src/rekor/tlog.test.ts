import { initializeTLog } from './tlog';

describe('TLog', () => {
  describe('#publicKey', () => {
    it('should be a public key', async () => {
      const subject = await initializeTLog();
      expect(subject.publicKey.type).toBe('public');
    });
  });

  describe('#logID', () => {
    it('should be a logID', async () => {
      const subject = await initializeTLog();
      expect(subject.logID).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('#log', () => {
    it('returns an entry', async () => {
      const proposedEntry = { foo: 'bar' };
      const subject = await initializeTLog();
      const result = await subject.log(proposedEntry);

      expect(Object.keys(result)).toHaveLength(1);
      const uuid = Object.keys(result)[0];
      expect(uuid).toMatch(/^[0-9a-f]{64}$/);

      const entry = result[uuid];
      expect(entry.body).toBeDefined();
      expect(JSON.parse(Buffer.from(entry.body, 'base64').toString())).toEqual(
        proposedEntry
      );
      expect(entry.integratedTime).toBeGreaterThan(0);
      expect(entry.logID).toBe(subject.logID);
      expect(entry.logIndex).toBeGreaterThan(0);
      expect(entry.verification).toBeDefined();
      expect(entry.verification?.signedEntryTimestamp).toBeDefined();
    });
  });
});
