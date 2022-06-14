import provider, { Provider } from './provider';

describe('add', () => {
  const p1: Provider = { getToken: () => Promise.resolve(undefined) };
  const p2: Provider = { getToken: () => Promise.resolve('abc123') };

  it('should add providers to the list', () => {
    provider.add(p1);
    provider.add(p2);

    const providerList = provider.all();
    expect(providerList).toHaveLength(2);
    expect(providerList).toContain(p1);
    expect(providerList).toContain(p2);
  });
});
