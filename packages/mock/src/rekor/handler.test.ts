import { fromPartial } from '@total-typescript/shoehorn';
import { rekorHandler } from './handler';
import { initializeTLog, TLog } from './tlog';

describe('rekorHandler', () => {
  describe('#path', () => {
    it('returns the correct path', async () => {
      const tlog = await initializeTLog();
      const handler = rekorHandler(tlog);
      expect(handler.path).toBe('/api/v1/log/entries');
    });
  });

  describe('#fn', () => {
    it('returns a function', async () => {
      const tlog = await initializeTLog();
      const handler = rekorHandler(tlog);
      expect(handler.fn).toBeInstanceOf(Function);
    });

    describe('when invoked', () => {
      const proposedEntry = {
        apiVersion: '0.0.1',
        kind: 'hashedrekord',
      };

      it('returns a tlog entry', async () => {
        const tlog = await initializeTLog();
        const { fn } = rekorHandler(tlog);

        const resp = await fn(JSON.stringify(proposedEntry));
        expect(resp.statusCode).toBe(201);

        // Check the response
        const body = JSON.parse(resp.response);
        expect(body).toBeDefined();
        expect(Object.keys(body)).toHaveLength(1);

        const uuid = Object.keys(body)[0];
        expect(uuid).toMatch(/^[0-9a-f]{64}$/);

        const entry = body[uuid];
        expect(entry.body).toBeDefined();
        expect(
          JSON.parse(Buffer.from(entry.body, 'base64').toString())
        ).toEqual(proposedEntry);
        expect(entry.integratedTime).toBeGreaterThan(0);
        expect(entry.logID).toBe(tlog.logID);
        expect(entry.logIndex).toBeGreaterThan(0);
        expect(entry.verification).toBeDefined();
        expect(entry.verification?.signedEntryTimestamp).toBeDefined();
      });

      describe('when the TLog raises an error', () => {
        const tlog = fromPartial<TLog>({
          log: async () => {
            throw new Error('oops');
          },
        });

        it('returns 400 error', async () => {
          const { fn } = rekorHandler(tlog, { strict: false });

          // Make a request
          const request = {};

          const resp = await fn(JSON.stringify(request));
          expect(resp.statusCode).toBe(400);
        });
      });
    });
  });
});
