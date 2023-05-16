import type { HashedRekorV001Schema } from './__generated__/hashedrekord';
import type {
  IntotoV001Schema,
  IntotoV002Schema,
} from './__generated__/intoto';

const INTOTO_KIND = 'intoto';
const HASHEDREKORD_KIND = 'hashedrekord';

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

export type ProposedEntry = ProposedHashedRekordEntry | ProposedIntotoEntry;

export type SearchLogQuery = {
  entryUUIDs?: Array<string>;
  logIndexes?: Array<number>;
  entries?: Array<ProposedEntry>;
};

export type { InclusionProof, LogEntry, SearchIndex } from './__generated__/';
export type { HashedRekorV001Schema } from './__generated__/hashedrekord';
export type {
  IntotoV001Schema,
  IntotoV002Schema,
} from './__generated__/intoto';
