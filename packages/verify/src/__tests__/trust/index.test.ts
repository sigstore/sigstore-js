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
import { VerificationError } from '../../error';
import { toTrustMaterial } from '../../trust';
import { trustedRoot } from '../__fixtures__/trust';

describe('toTrustMaterial', () => {
  it('returns a TrustMaterial', () => {
    const result = toTrustMaterial(trustedRoot);
    expect(result).toBeDefined();
    expect(result.certificateAuthorities).toHaveLength(2);
    expect(result.timestampAuthorities).toHaveLength(1);
    expect(result.tlogs).toHaveLength(1);
    expect(result.ctlogs).toHaveLength(3);

    expect(() => result.publicKey('FOO')).toThrowWithCode(
      VerificationError,
      'PUBLIC_KEY_ERROR'
    );
  });

  describe('when provided with keys', () => {
    const keys = {
      FOO: {
        rawBytes: Buffer.from(
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
          'base64'
        ),
        keyDetails: 0,
        validFor: {
          start: undefined,
        },
      },
      BAR: {
        rawBytes: Buffer.from(
          'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
          'base64'
        ),
        keyDetails: 0,
        validFor: {
          start: new Date(0),
          end: new Date(0),
        },
      },
    };

    it('implements a key look-up function', () => {
      const result = toTrustMaterial(trustedRoot, keys);
      expect(result.publicKey).toBeDefined();

      const key1 = result.publicKey('FOO');
      expect(key1).toBeDefined();
      expect(key1.validFor(new Date())).toBe(true);

      const key2 = result.publicKey('BAR');
      expect(key2).toBeDefined();
      expect(key2.validFor(new Date())).toBe(false);

      expect(() => result.publicKey('BEEF')).toThrowWithCode(
        VerificationError,
        'PUBLIC_KEY_ERROR'
      );
    });
  });

  describe('when provided with a key finder function', () => {
    const key = {
      /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
      publicKey: 'fake-key' as any,
      validFor: () => true,
    };

    it('uses the provided function', () => {
      const result = toTrustMaterial(trustedRoot, () => key);
      expect(result.publicKey('FOO')).toEqual(key);
    });
  });
});
