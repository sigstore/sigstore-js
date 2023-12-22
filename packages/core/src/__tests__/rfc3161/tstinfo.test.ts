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
import { ASN1Obj } from '../../asn1';
import { RFC3161TimestampVerificationError } from '../../rfc3161/error';
import { TSTInfo } from '../../rfc3161/tstinfo';

describe('TSTInfo', () => {
  const tstInfoDER = Buffer.from(
    '3081a602010106092b0601040183bf30023031300d060960864801650304020105000420853ff93762a06ddbf722c4ebe9ddd66d8f63ddaea97f521c3ecc20da7c976020021500b28ba80c86985e6559411e2d79dc465a8b911d4c180f32303233313232303231343931385a3003020101a036a434303231153013060355040a130c4769744875622c20496e632e31193017060355040313105453412054696d657374616d70696e67',
    'hex'
  );
  const asn1 = ASN1Obj.parseBuffer(tstInfoDER);
  const subject = new TSTInfo(asn1);

  describe('version', () => {
    it('returns the version', () => {
      expect(subject.version).toEqual(BigInt(1));
    });
  });

  describe('genTime', () => {
    it('returns the genTime', () => {
      expect(subject.genTime).toEqual(new Date('2023-12-20T21:49:18.000Z'));
    });
  });

  describe('messageImprintHashAlgorithm', () => {
    it('returns the messageImprintHashAlgorithm', () => {
      expect(subject.messageImprintHashAlgorithm).toEqual('sha256');
    });
  });

  describe('messageImprintHashedMessage', () => {
    it('returns the messageImprintHashedMessage', () => {
      expect(subject.messageImprintHashedMessage).toBeDefined();
    });
  });

  describe('verify', () => {
    describe('when the messageImprintHashedMessage matches the artifact', () => {
      const artifact = Buffer.from('hello, world\n');

      it('does not throw an error', () => {
        expect(() => subject.verify(artifact)).not.toThrow();
      });
    });

    describe('when the messageImprintHashedMessage does NOT match the artifact', () => {
      const artifact = Buffer.from('oops');

      it('does not throw an error', () => {
        expect(() => subject.verify(artifact)).toThrow(
          RFC3161TimestampVerificationError
        );
      });
    });
  });
});
