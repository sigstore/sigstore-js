import assert from 'assert';
import type { Handler, HandlerFn, HandlerFnResult } from '../shared.types';
import type { TLog } from './tlog';

const CREATE_ENTRY_PATH = '/api/v1/log/entries';

interface RekorHandlerOptions {
  strict?: boolean;
}

export function rekorHandler(
  tlog: TLog,
  opts: RekorHandlerOptions = {}
): Handler {
  return {
    path: CREATE_ENTRY_PATH,
    fn: createEntryHandler(tlog, opts),
  };
}

function createEntryHandler(tlog: TLog, opts: RekorHandlerOptions): HandlerFn {
  const strict = opts.strict ?? true;

  return async (body: string): Promise<HandlerFnResult> => {
    try {
      const proposedEntry = strict ? JSON.parse(body) : {};
      const tlogEntry = await tlog.log(proposedEntry);
      const response = JSON.stringify(tlogEntry);

      return { statusCode: 201, response, contentType: 'application/json' };
    } catch (e) {
      assert(e instanceof Error);
      return { statusCode: 400, response: e.message };
    }
  };
}
