import { fulcioHandler, initializeCA, initializeCTLog } from './fulcio';
import { mock } from './mock';
import { initializeTLog, rekorHandler } from './rekor';

const DEFAULT_FULCIO_URL = 'https://fulcio.sigstore.dev';
const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';

interface FulcioOptions {
  baseURL?: string;
  strict?: boolean;
}

interface RekorOptions {
  baseURL?: string;
  strict?: boolean;
}

export async function mockFulcio(options: FulcioOptions = {}) {
  const url = options.baseURL || DEFAULT_FULCIO_URL;
  const strict = options.strict ?? true;
  const handler = await initializeCTLog()
    .then((ctlog) => initializeCA(ctlog))
    .then((ca) => fulcioHandler(ca, { strict }));
  mock(url, handler);
}

export async function mockRekor(options: RekorOptions = {}) {
  const url = options.baseURL || DEFAULT_REKOR_URL;
  const strict = options.strict ?? true;
  const handler = await initializeTLog().then((tlog) =>
    rekorHandler(tlog, { strict })
  );
  mock(url, handler);
}

export type { HandlerFn } from './shared.types';
export {
  fulcioHandler,
  initializeCA,
  initializeCTLog,
  initializeTLog,
  rekorHandler,
};
