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
import { splitPEM } from './index';

describe('splitPEM', () => {
  const cert1 = '-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----';
  const cert2 = '-----BEGIN CERTIFICATE-----\nDEF\n-----END CERTIFICATE-----';

  describe('when certificate is empty', () => {
    it('should return empty array', () => {
      expect(splitPEM('')).toEqual([]);
    });
  });

  describe('when given a certificate with a single certificate', () => {
    it('returns an array with a single certificate', () => {
      expect(splitPEM(cert1)).toEqual([cert1]);
    });
  });

  describe('when given a certificate with multiple certificates', () => {
    it('returns an array with all the certificates', () => {
      const certs = splitPEM([cert1, cert2].join('\n'));

      expect(certs).toHaveLength(2);
      expect(certs[0]).toEqual(cert1);
      expect(certs[1]).toEqual(cert2);
    });
  });
});
