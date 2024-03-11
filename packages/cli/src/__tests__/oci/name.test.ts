/*
Copyright 2024 The Sigstore Authors.

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
import { parseImageName } from '../../oci/name';

describe('parseImageName', () => {
  it('parses a fully-quallified image names', () => {
    let name = parseImageName('ghcr.io/owner/repo:latest');
    expect(name.name).toEqual('ghcr.io/owner/repo');
    expect(name.tag).toEqual('latest');
    expect(name.digest).toBeUndefined();

    name = parseImageName(
      'ghcr.io/repo@sha1:f99c369892016a1f48a2eee9e69eaf96614b7281'
    );
    expect(name.name).toEqual('ghcr.io/repo');
    expect(name.digest).toEqual(
      'sha1:f99c369892016a1f48a2eee9e69eaf96614b7281'
    );
    expect(name.tag).toBeUndefined();

    name = parseImageName('localhost:8080/repo:_foo');
    expect(name.name).toEqual('localhost:8080/repo');
    expect(name.tag).toEqual('_foo');
    expect(name.digest).toBeUndefined();

    name = parseImageName(
      'a/b/c/d@sha256:62ce42bde6b4ba3aa0c42aa375025015b639b142c9b4daf89fcd422fc75f4a13'
    );
    expect(name.name).toEqual('a/b/c/d');
    expect(name.digest).toEqual(
      'sha256:62ce42bde6b4ba3aa0c42aa375025015b639b142c9b4daf89fcd422fc75f4a13'
    );
    expect(name.tag).toBeUndefined();
  });

  it('raises an error when the image name is invalid', () => {
    expect(() => parseImageName('repo')).toThrow();
    expect(() => parseImageName('')).toThrow();
    expect(() => parseImageName('a/b/c/d:-000')).toThrow();
    expect(() => parseImageName('a/b/c/d:.')).toThrow();
    expect(() =>
      parseImageName('a/b/c/d:sha1:f99c369892016a1f48a2eee9e69eaf96614b7281')
    ).toThrow();
  });
});
