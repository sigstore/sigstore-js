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
import { VerificationError } from '../../error';
import { verifyTLogSET } from '../../timestamp/set';

import type { TLogEntryWithInclusionPromise } from '@sigstore/bundle';
import type { TLogAuthority } from '../../trust';

describe('verifyTLogSET', () => {
  const keyBytes = Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    'base64'
  );
  const keyID = crypto.digest('sha256', keyBytes);

  const validTLog: TLogAuthority = {
    logID: keyID,
    publicKey: crypto.createPublicKey(keyBytes),
    validFor: { start: new Date(0), end: new Date('2100-01-01') },
  };

  const invalidTLog: TLogAuthority = {
    logID: Buffer.from('invalid'),
    publicKey: crypto.createPublicKey(keyBytes),
    validFor: { start: new Date(0), end: new Date('2100-01-01') },
  };

  const entry: TLogEntryWithInclusionPromise = fromPartial(
    TransparencyLogEntry.fromJSON({
      logIndex: '6757503',
      logId: { keyId: 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=' },
      kindVersion: { kind: 'hashedrekord', version: '0.0.1' },
      integratedTime: '1667957590',
      inclusionPromise: {
        signedEntryTimestamp:
          'MEUCIFUNcHgHB318gCNJR0/CH4E0daODbnfePyzKCDqrt3twAiEA9N+ZObaLwVJwvOtPgkfoBa5NzjTH0eC06YBlOyZlMiY=',
      },
      inclusionProof: undefined,
      canonicalizedBody:
        'eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2OGU2NTZiMjUxZTY3ZTgzNThiZWY4NDgzYWIwZDUxYzY2MTlmM2U3YTFhOWYwZTc1ODM4ZDQxZmYzNjhmNzI4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJSHM1YVV1bHExSHBSK2Z3bVNLcExrL29Bd3E1TzlDRE5GSGhaQUtmRzVHbUFpQndjVm5mMm9ienNDR1ZsZjBBSXZidkhyMjFOWHQ3dHBMQmw0K0JyaDZPS0E9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTnZSRU5EUVdsaFowRjNTVUpCWjBsVlpYWmhaU3R1VEZFNGJXYzJUM2xQUWpRelRVdEtNVEJHTWtORmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEplRTFVUVRWTlJFVjZUWHBCTlZkb1kwNU5ha2w0VFZSQk5VMUVSVEJOZWtFMVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVU1UkdKWlFrbE5VVXgwVjJJMlNqVm5kRXcyT1dwblVuZDNSV1prZEZGMFMzWjJSelFLSzI4elducHNUM0p2U25Cc2NGaGhWbWRHTm5kQ1JHOWlLeXR5VGtjNUwwRjZVMkZDYlVGd2EwVjNTVFV5V0VKcVYzRlBRMEZWVlhkblowWkNUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZXU1VsR0NtTXdPSG8yZFZZNVdUazJVeXQyTlc5RVltSnRTRVZaZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBoM1dVUldVakJTUVZGSUwwSkNWWGRGTkVWU1dXNUtjRmxYTlVGYVIxWnZXVmN4YkdOcE5XcGlNakIzVEVGWlMwdDNXVUpDUVVkRWRucEJRZ3BCVVZGbFlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVlpNamwwVERKNGRsb3liSFZNTWpsb1pGaFNiMDFKUjB0Q1oyOXlRbWRGUlVGa1dqVkJaMUZEQ2tKSWQwVmxaMEkwUVVoWlFUTlVNSGRoYzJKSVJWUktha2RTTkdOdFYyTXpRWEZLUzFoeWFtVlFTek12YURSd2VXZERPSEEzYnpSQlFVRkhSVmRuVlVjS1VYZEJRVUpCVFVGU2VrSkdRV2xGUVd4TGVXTk5Ra015Y1N0UlRTdHRZM1EyTUZKT1JVNTRjRlZTU0dWek5uWm5UMEpYWkhnM01WaGpXR2REU1VGMGJncE5lbmN2WTBKM05XZ3dhSEpaU2poaU1WQkthbTk0YmpOck1VNHlWR1JuYjJaeGRrMW9ZbE5VVFVGdlIwTkRjVWRUVFRRNVFrRk5SRUV5WjBGTlIxVkRDazFSUXpKTFRFWlpVMmxFTHl0VE1WZEZjM2xtT1dONlpqVXlkeXRGTlRjM1NHazNOM0k0Y0VkVlRURnlVUzlDZW1jeFlVZDJVWE13TDJ0Qlp6TlRMMG9LVTBSblEwMUZaRTQxWkVsVE1IUlNiVEZUVDAxaVQwWmpWeXN4ZVhwU0swOXBRMVpLTjBSV1JuZFZaRWt6UkM4M1JWSjRkRTQ1WlM5TVNqWjFZVkp1VWdvdlUyRnVjbmM5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19',
    })
  );

  describe('when there is a matching TLogInstance', () => {
    const tlogs = [invalidTLog, validTLog];

    describe('when the SET can be verified', () => {
      it('does NOT throw an error', () => {
        expect(verifyTLogSET(entry, tlogs)).toBeUndefined();
      });
    });

    describe('when the SET can NOT be verified', () => {
      const invalidEntry = { ...entry };

      beforeEach(() => {
        invalidEntry.integratedTime = '1';
      });

      it('throws an error', () => {
        expect(() => verifyTLogSET(invalidEntry, tlogs)).toThrowWithCode(
          VerificationError,
          'TLOG_INCLUSION_PROMISE_ERROR'
        );
      });
    });

    describe('when the public key for the matching TLogInstance is not valid', () => {
      describe('when the public key has a start after the integrated time', () => {
        const tlogs = [
          {
            ...validTLog,
            validFor: { start: new Date(), end: new Date('2999-01-01') },
          },
        ];

        it('throws an error', () => {
          expect(() => verifyTLogSET(entry, tlogs)).toThrowWithCode(
            VerificationError,
            'TLOG_INCLUSION_PROMISE_ERROR'
          );
        });
      });

      describe('when the public key has an end before the integrated time', () => {
        const tlogs = [
          {
            ...validTLog,
            validFor: { start: new Date(0), end: new Date(0) },
          },
        ];

        it('throws an error', () => {
          expect(() => verifyTLogSET(entry, tlogs)).toThrowWithCode(
            VerificationError,
            'TLOG_INCLUSION_PROMISE_ERROR'
          );
        });
      });
    });
  });

  describe('when there is NO matching TLogInstance', () => {
    const tlogs = [invalidTLog];

    it('throws an error', () => {
      expect(() => verifyTLogSET(entry, tlogs)).toThrowWithCode(
        VerificationError,
        'TLOG_INCLUSION_PROMISE_ERROR'
      );
    });
  });
});
