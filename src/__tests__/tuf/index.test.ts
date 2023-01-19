import { getTrustedRoot } from '../../tuf';

describe('getTrustedRoot', () => {
  it('returns the bundled trust root', () => {
    const root = getTrustedRoot();
    expect(root).toBeDefined();
    expect(root.mediaType).toEqual(
      'application/vnd.dev.sigstore.trustedroot+json;version=0.1'
    );
  });
});
