import { getKeys } from './keys';

describe('getKeys', () => {
  it('foo', () => {
    const keys = getKeys();
    expect(
      keys['c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d']
    ).toBeTruthy();
  });
});
