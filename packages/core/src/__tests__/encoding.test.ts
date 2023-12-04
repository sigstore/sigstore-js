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
import * as encoding from '..//encoding';

describe('encoding', () => {
  const testData = [
    // Example w/ padding
    {
      decoded: 'hello world',
      encoded: 'aGVsbG8gd29ybGQ=',
      urlEncoded: 'aGVsbG8gd29ybGQ',
    },
    // Example w/o padding
    {
      decoded: 'abstractiveness',
      encoded: 'YWJzdHJhY3RpdmVuZXNz',
      urlEncoded: 'YWJzdHJhY3RpdmVuZXNz',
    },
    // Example with URL-unsafe chars
    {
      decoded: 'a??~}~z',
      encoded: 'YT8/fn1+eg==',
      urlEncoded: 'YT8_fn1-eg',
    },
  ];

  describe('base64Encode', () => {
    it('encodes a string to base64', () => {
      testData.forEach((entry) => {
        expect(encoding.base64Encode(entry.decoded)).toBe(entry.encoded);
      });
    });
  });

  describe('base64Decode', () => {
    it('decodes a base64 string', () => {
      testData.forEach((entry) => {
        expect(encoding.base64Decode(entry.encoded)).toBe(entry.decoded);
      });
    });
  });
});
