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
import { fromDER, split, toDER } from '../../util/pem';

describe('pem', () => {
  const cert1 =
    '-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----\n';
  const cert2 =
    '-----BEGIN CERTIFICATE-----\nDEFG\n-----END CERTIFICATE-----\n';

  describe('split', () => {
    describe('when certificate is empty', () => {
      it('should return empty array', () => {
        expect(split('')).toEqual([]);
      });
    });

    describe('when given a certificate with a single certificate', () => {
      it('returns an array with a single certificate', () => {
        expect(split(cert1)).toEqual([cert1]);
      });
    });

    describe('when given a certificate with multiple certificates', () => {
      it('returns an array with all the certificates', () => {
        const certs = split([cert1, cert2].join('\n'));

        expect(certs).toHaveLength(2);
        expect(certs[0]).toEqual(cert1);
        expect(certs[1]).toEqual(cert2);
      });
    });
  });

  describe('toDER', () => {
    it('returns a DER-encoded certificate', () => {
      const der = toDER(cert1);
      expect(der).toEqual(Buffer.from('ABCD', 'base64'));
    });
  });

  describe('fromDER', () => {
    const cert =
      '-----BEGIN CERTIFICATE-----\nMIICoTCCAiagAwIBAgIUDnU0n6QHoPRvPj6b2Ee38VOD4TswCgYIKoZIzj0EAwMw\ncm1l\n-----END CERTIFICATE-----\n';

    const der = toDER(cert);

    it('returns a PEM-encoded certificate', () => {
      const pem = fromDER(der);
      expect(pem).toEqual(cert);
    });
  });
});
