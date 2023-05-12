/*
Copyright 2022 GitHub, Inc

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

import { Hasher } from '../../merkle/digest';

describe('Hasher', () => {
  it('should create an instance', () => {
    const hasher = new Hasher();
    expect(hasher).toBeTruthy();
  });

  describe('when the hash algorithm is sha256', () => {
    const subject = new Hasher('sha256');

    describe('size', () => {
      it('is 32', () => {
        expect(subject.size()).toBe(32);
      });
    });

    describe('hashLeaf', () => {
      it('hashes a leaf', () => {
        const hash = subject.hashLeaf(Buffer.from('hello'));

        expect(hash).toEqual(
          Buffer.from('iipcm3aIJ95alVLDigRMZpWcaPbS8htSYK9U0vh9uCc=', 'base64')
        );
      });
    });

    describe('hashChildren', () => {
      it('hashes the children', () => {
        const l = Buffer.from('left');
        const r = Buffer.from('right');
        const hash = subject.hashChildren(l, r);

        expect(hash).toEqual(
          Buffer.from('I8JKzKnpqpZvObkOQVTZEzNPoWDjX8vNA05nO/szOa0=', 'base64')
        );
      });
    });
  });
});
