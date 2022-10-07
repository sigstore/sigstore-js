import { getKey } from './keys';

describe('getKey', () => {
  it('foo', () => {
    expect(
      getKey('c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d')
    ).toBeTruthy();
  });
});
