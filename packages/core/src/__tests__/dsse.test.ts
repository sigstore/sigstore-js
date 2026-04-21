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
import { preAuthEncoding } from '../dsse';

describe('preAuthEncoding', () => {
  const payloadType = 'text/plain';
  const payload = Buffer.from('Hello, World!', 'utf8');

  it('should return the correct pre-auth encoding', () => {
    const pae = preAuthEncoding(payloadType, payload);
    expect(pae).toEqual(Buffer.from('DSSEv1 10 text/plain 13 Hello, World!'));
  });

  it('should use utf-8 byte length for non-ASCII payloadType', () => {
    // U+00E9 (é) is 2 bytes in UTF-8
    const nonAsciiType = 'application/typ\u00e9';
    const pae = preAuthEncoding(nonAsciiType, payload);

    const typeBytes = Buffer.from(nonAsciiType, 'utf-8');
    expect(typeBytes.length).toBe(17); // 16 ASCII chars + 2 byte é = 17

    const expected = Buffer.concat([
      Buffer.from(`DSSEv1 ${typeBytes.length} `, 'ascii'),
      typeBytes,
      Buffer.from(` ${payload.length} `, 'ascii'),
      payload,
    ]);
    expect(pae).toEqual(expected);
  });

  it('should produce distinct PAE for Unicode payloadType variants', () => {
    // U+0174 has same low byte as 't' (0x74) — the old ascii
    // encoding would have mapped both to the same byte
    const original = preAuthEncoding('text/plain', payload);
    const mutant = preAuthEncoding('\u0174ext/plain', payload);

    expect(original).not.toEqual(mutant);
  });
});
