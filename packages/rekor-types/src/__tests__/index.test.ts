import * as rekor from '../index';

describe('rekor-types', () => {
  it('should export types', () => {
    const entry: rekor.LogEntry = {} as rekor.LogEntry;
    expect(entry).toBeDefined();

    const searchLogQuery: rekor.SearchLogQuery = {} as rekor.SearchLogQuery;
    expect(searchLogQuery).toBeDefined();

    const inclusionProof: rekor.InclusionProof = {} as rekor.InclusionProof;
    expect(inclusionProof).toBeDefined();

    const searchIndex: rekor.SearchIndex = {} as rekor.SearchIndex;
    expect(searchIndex).toBeDefined();

    const hashedRekorV001Schema: rekor.HashedRekorV001Schema =
      {} as rekor.HashedRekorV001Schema;
    expect(hashedRekorV001Schema).toBeDefined();

    const intotoV001Schema: rekor.IntotoV001Schema =
      {} as rekor.IntotoV001Schema;
    expect(intotoV001Schema).toBeDefined();

    const intotoV002Schema: rekor.IntotoV002Schema =
      {} as rekor.IntotoV002Schema;
    expect(intotoV002Schema).toBeDefined();

    const proposedEntry: rekor.ProposedEntry = {} as rekor.ProposedEntry;
    expect(proposedEntry).toBeDefined();

    const proposedHashedRekordEntry: rekor.ProposedHashedRekordEntry =
      {} as rekor.ProposedHashedRekordEntry;
    expect(proposedHashedRekordEntry).toBeDefined();

    const proposedIntotoEntry: rekor.ProposedIntotoEntry =
      {} as rekor.ProposedIntotoEntry;
    expect(proposedIntotoEntry).toBeDefined();
  });
});
