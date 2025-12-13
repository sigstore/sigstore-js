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
import { crypto } from '@sigstore/core';
import { TransparencyLogEntry } from '@sigstore/protobuf-specs';
import { fromPartial } from '@total-typescript/shoehorn';
import { getTLogTimestamp } from '../../timestamp/index';

import type { TransparencyLogEntry as TLogEntry } from '@sigstore/bundle';

describe('getTLogTimestamp', () => {
  // Actual public key for public-good Rekor
  const keyBytes = Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    'base64'
  );
  const keyID = crypto.digest('sha256', keyBytes);

  describe('when a valid bundle with inclusion promise is provided', () => {
    const tlogEntry: TLogEntry = fromPartial(
      TransparencyLogEntry.fromJSON({
        logId: { keyId: 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=' },
        integratedTime: '1667957590',
      })
    );

    it('does NOT throw an error', () => {
      const result = getTLogTimestamp(tlogEntry);

      expect(result.type).toEqual('transparency-log');
      expect(result.logID).toEqual(keyID);
      expect(result.timestamp).toBeDefined();
    });
  });
});
