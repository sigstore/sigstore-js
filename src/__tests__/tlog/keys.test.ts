/*
Copyright 2022 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { getKeys } from '../../tlog/keys';

describe('getKeys', () => {
  const expectedLogID =
    'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d';

  it('loads the static Rekor public key', () => {
    const keys = getKeys();
    expect(keys).toHaveProperty(expectedLogID);
    expect(keys[expectedLogID]).toBeTruthy();
  });
});
