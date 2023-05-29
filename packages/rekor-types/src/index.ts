import type { DSSEV001Schema } from './__generated__/dsse';
import type { HashedRekorV001Schema } from './__generated__/hashedrekord';
import type {
  IntotoV001Schema,
  IntotoV002Schema,
} from './__generated__/intoto';

const DSSE_KIND = 'dsse';
const INTOTO_KIND = 'intoto';
const HASHEDREKORD_KIND = 'hashedrekord';

export type ProposedDSSEEntry = {
  apiVersion: '0.0.1';
  kind: typeof DSSE_KIND;
  spec: DSSEV001Schema;
};

export type ProposedHashedRekordEntry = {
  apiVersion: '0.0.1';
  kind: typeof HASHEDREKORD_KIND;
  spec: HashedRekorV001Schema;
};

export type ProposedIntotoEntry =
  | {
      apiVersion: '0.0.1';
      kind: typeof INTOTO_KIND;
      spec: IntotoV001Schema;
    }
  | {
      apiVersion: '0.0.2';
      kind: typeof INTOTO_KIND;
      spec: IntotoV002Schema;
    };

export type ProposedEntry =
  | ProposedDSSEEntry
  | ProposedHashedRekordEntry
  | ProposedIntotoEntry;

export type SearchLogQuery = {
  entryUUIDs?: Array<string>;
  logIndexes?: Array<number>;
  entries?: Array<ProposedEntry>;
};

export type { InclusionProof, LogEntry, SearchIndex } from './__generated__/';
export type { DSSEV001Schema } from './__generated__/dsse';
export type { HashedRekorV001Schema } from './__generated__/hashedrekord';
export type {
  IntotoV001Schema,
  IntotoV002Schema,
} from './__generated__/intoto';
