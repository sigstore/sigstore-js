import { getName } from './index';

describe('getName', () => {
  it('is sigstore-node', () => {
    expect(getName()).toEqual('sigstore-node');
  });
});
