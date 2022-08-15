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
import nock from 'nock';
import * as dsse from './dsse';
import { base64Decode } from './util';

describe('sign', () => {
  const fulcioBaseURL = 'http://localhost:8001';
  const rekorBaseURL = 'http://localhost:8002';
  const jwtPayload = {
    iss: 'https://example.com',
    sub: 'foo@bar.com',
  };
  const jwt = `.${Buffer.from(JSON.stringify(jwtPayload)).toString('base64')}.`;

  const options = {
    fulcioBaseURL,
    rekorBaseURL,
    identityToken: jwt,
  };

  // Input
  const payload = Buffer.from('Hello, world!');
  const payloadType = 'text/plain';

  describe('when Fulcio returns an error', () => {
    beforeEach(() => {
      nock(fulcioBaseURL).post('/api/v1/signingCert').reply(500, {});
    });

    it('returns an error', async () => {
      await expect(dsse.sign(payload, payloadType, options)).rejects.toThrow(
        'HTTP Error: 500 Internal Server Error'
      );
    });
  });

  describe('when Fulcio returns successfully', () => {
    // Fulcio output
    const certificate = `-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----`;

    beforeEach(() => {
      // Mock Fulcio request
      nock(fulcioBaseURL)
        .matchHeader('Accept', 'application/pem-certificate-chain')
        .matchHeader('Content-Type', 'application/json')
        .matchHeader('Authorization', `Bearer ${jwt}`)
        .post('/api/v1/signingCert', {
          publicKey: { content: /.+/i },
          signedEmailAddress: /.+/i,
        })
        .reply(200, certificate);
    });

    describe('when Rekor returns successfully', () => {
      // Rekor output
      const signature = 'ABC123';
      const b64Cert = Buffer.from(certificate).toString('base64');
      const uuid =
        '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

      const signatureBundle = {
        spec: {
          signature: {
            content: signature,
            publicKey: { content: b64Cert },
          },
        },
      };

      const rekorEntry = {
        [uuid]: {
          body: Buffer.from(JSON.stringify(signatureBundle)).toString('base64'),
          integratedTime: 1654015743,
          logID:
            'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
          logIndex: 2513258,
          verification: {
            signedEntryTimestamp:
              'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
          },
        },
      };

      beforeEach(() => {
        // Mock Rekor request
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries')
          .reply(201, rekorEntry);
      });

      it('returns an envelope', async () => {
        const envelope = await dsse.sign(payload, payloadType, options);

        expect(envelope).toEqual({
          payload: payload.toString('base64'),
          payloadType: payloadType,
          signatures: [
            {
              keyid: '',
              sig: expect.any(String),
            },
          ],
        });
      });
    });

    describe('when Rekor returns an error', () => {
      beforeEach(() => {
        nock(rekorBaseURL)
          .matchHeader('Accept', 'application/json')
          .matchHeader('Content-Type', 'application/json')
          .post('/api/v1/log/entries')
          .reply(500, {});
      });

      it('returns an error', async () => {
        await expect(dsse.sign(payload, payloadType, options)).rejects.toThrow(
          'HTTP Error: 500 Internal Server Error'
        );
      });
    });
  });
});

describe('verify', () => {
  const rekorBaseURL = 'http://localhost:8002';
  const options = { rekorBaseURL };

  const payload = Buffer.from('Hello, world!');

  // Signature that could have been created for the PAE struct wrapping the payload
  const signature =
    'MEUCIHZr6luUVXbHBAynBnAoPc1WedAl5AyA1bI5o4jqnVKiAiEA1LCAFxK37CAKJP0RwZ2a1mOeco3Z8BKbGueQrvBC+08=';

  // Cert that generated the signature above
  const signingCert =
    'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvVENDQWlhZ0F3SUJBZ0lVTnRkVUhHWjZWLzRUNE9QdjE1end6NTZubUZJd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJd056RTBNak16TURFd1doY05Nakl3TnpFME1qTTBNREV3V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVOcFVMeHF3VHVUaDMxRndBTUt2Nkg1SURFZWRjUmJSL3RyVEwKc2RIOW1JMWJwSVR3OXB5S2RYZ3VuT2NoMEpaT2ZpSUR5ZlVRK2xTdDhOdG56Rzk1U3FPQ0FVVXdnZ0ZCTUE0RwpBMVVkRHdFQi93UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREF6QWRCZ05WSFE0RUZnUVVRellTCmdTTzhtbTFrdHpTSWdrVEhack1ZNXo4d0h3WURWUjBqQkJnd0ZvQVUzOVBwejFZa0VaYjVxTmpwS0ZXaXhpNFkKWkQ4d0h3WURWUjBSQVFIL0JCVXdFNEVSWW5KcFlXNUFaR1ZvWVcxbGNpNWpiMjB3TEFZS0t3WUJCQUdEdnpBQgpBUVFlYUhSMGNITTZMeTluYVhSb2RXSXVZMjl0TDJ4dloybHVMMjloZFhSb01JR0tCZ29yQmdFRUFkWjVBZ1FDCkJId0VlZ0I0QUhZQUNHQ1M4Q2hTLzJoRjBkRnJKNFNjUldjWXJCWTl3empTYmVhOElnWTJiM0lBQUFHQi93eGgKeVFBQUJBTUFSekJGQWlFQXZ1TitHVTZzdUdteWRHZ2F4RG9tQkRUSDJyS21FVm5sMzNuLy82a1NpeElDSUdxVQphTk51VFhSclBuaFg5NkxwRThwanZZRzE5dkcvbS9FSmZWMmRGQ0FJTUFvR0NDcUdTTTQ5QkFNREEya0FNR1lDCk1RRHhMNFZENVkvU3BiQU4vYlVQTTF5Zkd0NjRiZUN4NS8vYTJHQ3pxbzBza2gxeTU1NTlxNFVxd2lLTVhzdnUKVW1jQ01RQytEOEtiNVF0bXNIVnBTWjhycXhaRDlmazI0cWlmb3hKdXZyUHFjMDVaVzRIVlRJdDFOeG5CNWRiTwpOWmgybnBBPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDR2pDQ0FhR2dBd0lCQWdJVUFMblZpVmZuVTBickphc21Sa0hybi9VbmZhUXdDZ1lJS29aSXpqMEVBd013CktqRVZNQk1HQTFVRUNoTU1jMmxuYzNSdmNtVXVaR1YyTVJFd0R3WURWUVFERXdoemFXZHpkRzl5WlRBZUZ3MHkKTWpBME1UTXlNREEyTVRWYUZ3MHpNVEV3TURVeE16VTJOVGhhTURjeEZUQVRCZ05WQkFvVERITnBaM04wYjNKbApMbVJsZGpFZU1Cd0dBMVVFQXhNVmMybG5jM1J2Y21VdGFXNTBaWEp0WldScFlYUmxNSFl3RUFZSEtvWkl6ajBDCkFRWUZLNEVFQUNJRFlnQUU4UlZTL3lzSCtOT3Z1RFp5UEladGlsZ1VGOU5sYXJZcEFkOUhQMXZCQkgxVTVDVjcKN0xTUzdzMFppSDRuRTdIdjdwdFM2THZ2Ui9TVGs3OThMVmdNekxsSjRIZUlmRjN0SFNhZXhMY1lwU0FTcjFrUwowTi9SZ0JKei85aldDaVhubzNzd2VUQU9CZ05WSFE4QkFmOEVCQU1DQVFZd0V3WURWUjBsQkF3d0NnWUlLd1lCCkJRVUhBd013RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBZEJnTlZIUTRFRmdRVTM5UHB6MVlrRVpiNXFOanAKS0ZXaXhpNFlaRDh3SHdZRFZSMGpCQmd3Rm9BVVdNQWVYNUZGcFdhcGVzeVFvWk1pMENyRnhmb3dDZ1lJS29aSQp6ajBFQXdNRFp3QXdaQUl3UENzUUs0RFlpWllEUElhRGk1SEZLbmZ4WHg2QVNTVm1FUmZzeW5ZQmlYMlg2U0pSCm5aVTg0LzlEWmRuRnZ2eG1BakJPdDZRcEJsYzRKLzBEeHZrVENxcGNsdnppTDZCQ0NQbmpkbElCM1B1M0J4c1AKbXlnVVk3SWkyemJkQ2RsaWlvdz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQjl6Q0NBWHlnQXdJQkFnSVVBTFpOQVBGZHhIUHdqZURsb0R3eVlDaEFPLzR3Q2dZSUtvWkl6ajBFQXdNdwpLakVWTUJNR0ExVUVDaE1NYzJsbmMzUnZjbVV1WkdWMk1SRXdEd1lEVlFRREV3aHphV2R6ZEc5eVpUQWVGdzB5Ck1URXdNRGN4TXpVMk5UbGFGdzB6TVRFd01EVXhNelUyTlRoYU1Db3hGVEFUQmdOVkJBb1RESE5wWjNOMGIzSmwKTG1SbGRqRVJNQThHQTFVRUF4TUljMmxuYzNSdmNtVXdkakFRQmdjcWhrak9QUUlCQmdVcmdRUUFJZ05pQUFUNwpYZUZUNHJiM1BRR3dTNElhanRMazMvT2xucGdhbmdhQmNsWXBzWUJyNWkrNHluQjA3Y2ViM0xQME9JT1pkeGV4Clg2OWM1aVZ1eUpSUStIejA1eWkrVUYzdUJXQWxIcGlTNXNoMCtIMkdIRTdTWHJrMUVDNW0xVHIxOUw5Z2c5MmoKWXpCaE1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJSWQp3QjVma1VXbFpxbDZ6SkNoa3lMUUtzWEYrakFmQmdOVkhTTUVHREFXZ0JSWXdCNWZrVVdsWnFsNnpKQ2hreUxRCktzWEYrakFLQmdncWhrak9QUVFEQXdOcEFEQm1BakVBajFuSGVYWnArMTNOV0JOYStFRHNEUDhHMVdXZzF0Q00KV1AvV0hQcXBhVm8wamhzd2VORlpnU3MwZUU3d1lJNHFBakVBMldCOW90OThzSWtvRjN2WllkZDMvVnRXQjViOQpUTk1lYTdJeC9zdEo1VGZjTExlQUJMRTRCTkpPc1E0dm5CSEoKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==';

  describe('when the signature and the cert match', () => {
    const envelope = {
      payloadType: 'text/plain',
      payload: payload.toString('base64'),
      signatures: [{ keyid: '', sig: signature }],
    };

    it('returns true', async () => {
      const flag = await dsse.verify(
        envelope,
        base64Decode(signingCert),
        options
      );
      expect(flag).toBe(true);
    });
  });

  describe('when the signature and the do NOT cert match', () => {
    const envelope = {
      payloadType: 'text/plain',
      payload: payload.toString('base64'),
      signatures: [{ keyid: '', sig: '' }],
    };

    it('returns false', async () => {
      const flag = await dsse.verify(
        envelope,
        base64Decode(signingCert),
        options
      );
      expect(flag).toBe(false);
    });
  });
});
