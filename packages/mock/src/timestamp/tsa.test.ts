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

import * as pkijs from 'pkijs';
import { generateKeyPair } from '../util/key';
import { initializeTSA, TimestampRequest } from './tsa';

const OID_TSA_POLICY = '1.3.6.1.4.1.57264.2';
const OID_SHA256_ALGO_ID = '2.16.840.1.101.3.4.2.1';

describe('TSA', () => {
  const keyPair = generateKeyPair('prime256v1');
  describe('rootCertificate', () => {
    it('returns the root certificate', async () => {
      const tsa = await initializeTSA(keyPair);
      const root = tsa.rootCertificate;

      expect(root).toBeDefined();

      const cert = pkijs.Certificate.fromBER(root);
      expect(cert.issuer.typesAndValues[0].value.valueBlock.value).toBe('tsa');
      expect(cert.issuer.typesAndValues[1].value.valueBlock.value).toBe(
        'sigstore.mock'
      );
    });
  });

  describe('#timestamp', () => {
    const request: TimestampRequest = {
      hashAlgorithmOID: OID_SHA256_ALGO_ID,
      artifactHash: Buffer.from('hello world'),
      nonce: 12345,
      policyOID: OID_TSA_POLICY,
    };

    it('returns a timestamp', async () => {
      const tsa = await initializeTSA(keyPair);
      const result = await tsa.timestamp(request);
      expect(result).toBeDefined();

      const timestamp = pkijs.TimeStampResp.fromBER(result);
      expect(timestamp.status.status).toBe(0);
      expect(timestamp.timeStampToken?.contentType).toBe(
        '1.2.840.113549.1.7.2'
      );
    });
  });
});
