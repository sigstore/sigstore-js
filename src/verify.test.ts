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
import { Rekor } from './client';
import { base64Decode } from './encoding';
import { Verifier } from './verify';
import { SigstoreDSSEBundle, DSSE } from './bundle';

describe('Verifier', () => {
  const rekorBaseURL = 'http://localhost:8002';
  const rekor = new Rekor({ baseURL: rekorBaseURL });
  const subject = new Verifier({ rekor });

  describe('#verify', () => {
    const payload = Buffer.from('Hello, world!');
    const signature =
      'MEUCIFRsQUBCo06j+lKpCx2XaaVS0N+f6czW8aBsgek5aeoZAiEA/A2KUxPCvxFjFu184a1256IGVmiFfZagq5Pm0yUgQLU=';

    // Cert that could have generated the signature above
    const signingCert =
      'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN1RENDQWoyZ0F3SUJBZ0lVVmV0U01RemZUbXVrTTlDSnV0KytId3AvWThzd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd05qQTRNVGN3TXpFeVdoY05Nakl3TmpBNE1UY3hNekV5V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV0T2N5a0lMREVTVDNwN2JkZ24zMjYyS1pWSXlHL0F2SDl6ZG0KUVdDMXlpR2tVV2ZqVVF5aCtWSTVselEyQXFxdVR3QlFYZDdCcDRlaFFwYzRYaVpqQTZPQ0FWd3dnZ0ZZTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVKWi8xCmRpTEhENDNvdUhneWhrcnF6QnRFTGt3d0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d09RWURWUjBSQVFIL0JDOHdMWUVyWVhKMGMybG5ibVZ5UUdSbGFHRnRaWEl5TkM1cFlXMHVaM05sY25acApZMlZoWTJOdmRXNTBMbU52YlRBcEJnb3JCZ0VFQVlPL01BRUJCQnRvZEhSd2N6b3ZMMkZqWTI5MWJuUnpMbWR2CmIyZHNaUzVqYjIwd2dZb0dDaXNHQVFRQjFua0NCQUlFZkFSNkFIZ0FkZ0FJWUpMd0tGTC9hRVhSMFdzbmhKeEYKWnhpc0ZqM0RPTkp0NXJ3aUJqWnZjZ0FBQVlGRVJTak1BQUFFQXdCSE1FVUNJUURRYUNLYlhtTnBqWDExSVVhZwpoNk5DbWtsaURwR3pBTXdEY0xaWHYzVUdyd0lnY29zNGZqR1RiOGFEb2NhNk9FOEowNEJWYko1VzB1OHNyU1FjCjF6bDdhd0F3Q2dZSUtvWkl6ajBFQXdNRGFRQXdaZ0l4QUpERlc4bGJDVUhPL1Qzb0Z2TVc3WXhYQlBWdXM2UjkKN0xhY0N4aE9zbHpYWUFhMXdtWks0VXlnTHZFS3pITER1Z0l4QVBpRlI2RWtBRWtCYkJzQ2Q4aU1xZ3R0Rmp1QQpaQURrWjFiTGdaU1VPSEVyVjUvMGluZDFaSGtNcnE1ZHJDeFpvUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K';

    describe('when the signature and the cert match', () => {
      it('returns true', async () => {
        const verified = await subject.verify(
          payload,
          signature,
          base64Decode(signingCert)
        );

        expect(verified).toBe(true);
      });
    });

    describe('when the signature and the cert do NOT match', () => {
      it('returns false', async () => {
        const verified = await subject.verify(
          payload,
          '',
          base64Decode(signingCert)
        );

        expect(verified).toBe(false);
      });
    });
  });

  describe('#verifyDSSE', () => {
    const payload = Buffer.from('hello world');
    const payloadType = 'text/plain';
    const signature =
      'MEQCICI87pUJwMdF/AuTxb+i9OFWvzIOoxEnJx0oEqayXEBzAiAzjiZJ3FvcGINs+5oZrZNh36g3GKAnv6Ssr+J9eOGHHg==';

    // Cert that could have generated the signature above
    const signingCert =
      'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvakNDQWllZ0F3SUJBZ0lVSTBIWnd0ZWJ1bnNzWk5ob21xSkd2RjVXNXIwd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd09ERTVNVGMxTURVNVdoY05Nakl3T0RFNU1UZ3dNRFU1V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUUwQWUxU1hiWHZJN2UrY082NXlMR2k3ek0rR1R0NDllSTdkelAKNEpBYy9KRHVYYk50T3N6R3cydDNMc2R2N2t2NWZ4YTZ2R3UwMzYzdEl2NlF4QVo3WTZPQ0FVWXdnZ0ZDTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVUzUHYwCnAzUEdxdWJ2TDc5Nm1EaVRJUlN5Q2xnd0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0h3WURWUjBSQVFIL0JCVXdFNEVSWW5KcFlXNUFaR1ZvWVcxbGNpNWpiMjB3TEFZS0t3WUJCQUdEdnpBQgpBUVFlYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJ4dloybHVMMjloZFhSb01JR0xCZ29yQmdFRUFkWjVBZ1FDCkJIMEVld0I1QUhjQUNHQ1M4Q2hTLzJoRjBkRnJKNFNjUldjWXJCWTl3empTYmVhOElnWTJiM0lBQUFHQ3R6ckgKK0FBQUJBTUFTREJHQWlFQWl5aWx5S3lsb21reUxGaGtIYUoyOFBua0NIQ3RrRGNkQ3VRVHVRMTg4dTRDSVFEagpUTHdrd1NDdEdLUGw0S3BNTXh3YkpOUzVxcC9PL2FHcVUvT291TGtETFRBS0JnZ3Foa2pPUFFRREF3TnBBREJtCkFqRUE5UWk4RksvNDZXKytPRmFHVFdUakVCVDVGa0Q5cExnTmZrTU5ldzVzVm4yaVF5QTJmSTJGOTNNSkp2ckwKbE5HK0FqRUEvYm95eUl5QklqZC9OYzRzaFppSlVtdEJLSU44ZVJZZWtBRVM1QklrSHMrK1d1U0xUUDhBQVVQZQpPT3VDM3NHLwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t';

    const envelope: DSSE = {
      payload: payload.toString('base64'),
      payloadType,
      signatures: [{ keyid: '', sig: signature }],
    };

    const bundle: SigstoreDSSEBundle = {
      attestationType: 'attestation/dsse',
      attestation: envelope,
      certificate: signingCert,
      integratedTime: 0,
      logID: '',
      logIndex: 0,
      signedEntryTimestamp: '',
    };

    describe('when the signature and the cert match', () => {
      it('returns true', async () => {
        const verified = await subject.verifyDSSE(bundle);
        expect(verified).toBe(true);
      });
    });

    describe('when the signature and the cert do NOT match', () => {
      it('returns false', async () => {
        const invalidBundle = { ...bundle };
        invalidBundle.attestation.payloadType = 'text/html';

        const verified = await subject.verifyDSSE(invalidBundle);

        expect(verified).toBe(false);
      });
    });
  });
});
