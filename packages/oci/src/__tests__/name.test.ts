/*
Copyright 2023 The Sigstore Authors.

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
import { parseImageName } from '../name';

describe('parseImageName', () => {
  it('parses a fully-quallified image names', () => {
    let name = parseImageName('ghcr.io/owner/repo');
    expect(name.registry).toEqual('ghcr.io');
    expect(name.path).toEqual('owner/repo');

    name = parseImageName('ghcr.io/repo');
    expect(name.registry).toEqual('ghcr.io');
    expect(name.path).toEqual('repo');

    name = parseImageName('localhost:8080/repo');
    expect(name.registry).toEqual('localhost:8080');
    expect(name.path).toEqual('repo');

    name = parseImageName('a/b/c/d');
    expect(name.registry).toEqual('a');
    expect(name.path).toEqual('b/c/d');
  });

  it('raises an error when the image name is invalid', () => {
    expect(() => parseImageName('repo')).toThrow();
    expect(() => parseImageName('')).toThrow();
  });
});
