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
import { fromPartial } from '@total-typescript/shoehorn';
import { filterTLogAuthorities } from '../../trust/filter';

import type { TLogAuthority } from '../../trust';

describe('filterTLogAuthorities', () => {
  const tlogInstances: TLogAuthority[] = [
    {
      logID: Buffer.from('log1'),
      publicKey: fromPartial({}),
      validFor: {
        start: new Date('2020-01-01'),
        end: new Date('2020-12-31'),
      },
    },
    {
      logID: Buffer.from('log2'),
      publicKey: fromPartial({}),
      validFor: {
        start: new Date('1900-01-01'),
        end: new Date('1900-12-31'),
      },
    },
    {
      logID: Buffer.from('log3'),
      publicKey: fromPartial({}),
      validFor: {
        start: new Date('2020-01-01'),
        end: new Date('2020-12-31'),
      },
    },
  ];

  describe('when filtering by date', () => {
    it('returns instances valid during the given date', () => {
      const tlogs = filterTLogAuthorities(tlogInstances, {
        targetDate: new Date('2020-02-01'),
      });

      expect(tlogs).toHaveLength(2);
      expect(tlogs[0].logID).toEqual(Buffer.from('log1'));
      expect(tlogs[1].logID).toEqual(Buffer.from('log3'));
    });
  });

  describe('when filtering by date and log ID', () => {
    it('returns instances valid during the given date for the given log ID', () => {
      const tlogs = filterTLogAuthorities(tlogInstances, {
        targetDate: new Date('1900-02-01'),
        logID: Buffer.from('log2'),
      });

      expect(tlogs).toHaveLength(1);
      expect(tlogs[0].logID).toEqual(Buffer.from('log2'));
    });
  });
});
