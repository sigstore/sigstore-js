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
import { TransparencyLogInstance } from '@sigstore/protobuf-specs';
import { SignedCertificateTimestamp } from '../../x509/sct';

describe('SignedCertificateTimestamp', () => {
  // These are values from a real SCT extension
  const logID =
    '086092f02852ff6845d1d16b27849c456718ac163dc338d26de6bc2206366f72';
  const timestamp = '0000018227c09e9c';
  const signature =
    '3045022100b9ecb0b5286feea20d442a409da8c5260bd6ae76b311d71faceff1c7fc93c85c02204e35e55d629a1a84f9a885e7621d9b3af9ed8e7ffd0260679139bda764c5e7d0';
  const sctBuffer = Buffer.from(
    '00' + // version
      logID + // logID
      timestamp + // timestamp
      '0000' + // extensionLength
      '04' + // hashAlgorithm
      '03' + // signatureAlgorithm
      '0047' + // signatureLength
      signature, // signature
    'hex'
  );

  describe('#parse', () => {
    describe('when the SCT is valid', () => {
      it('parses correctly', () => {
        const sct = SignedCertificateTimestamp.parse(sctBuffer);

        expect(sct.version).toEqual(0x00);
        expect(sct.logID).toStrictEqual(Buffer.from(logID, 'hex'));
        expect(sct.timestamp).toStrictEqual(Buffer.from(timestamp, 'hex'));
        expect(sct.extensions).toHaveLength(0);
        expect(sct.hashAlgorithm).toEqual(0x04);
        expect(sct.signatureAlgorithm).toEqual(0x03);
        expect(sct.signature).toStrictEqual(Buffer.from(signature, 'hex'));
      });
    });

    describe('when the SCT is invalid', () => {
      describe('when the SCT buffer is too short', () => {
        it('throws an error', () => {
          expect(() =>
            SignedCertificateTimestamp.parse(Buffer.from(''))
          ).toThrow('request past end of buffer');
        });
      });

      describe('when the SCT buffer is too long', () => {
        const sctBuffer = Buffer.from(
          '00' +
            logID +
            timestamp +
            '0000' +
            '04' +
            '03' +
            '0047' +
            signature +
            'DEADBEEF', // extra bytes
          'hex'
        );

        it('throws an error', () => {
          expect(() => SignedCertificateTimestamp.parse(sctBuffer)).toThrow(
            'SCT buffer length mismatch'
          );
        });
      });
    });
  });

  describe('#datetime', () => {
    const subject = SignedCertificateTimestamp.parse(sctBuffer);

    it('returns the parsed timestamp', () => {
      expect(subject.datetime).toEqual(new Date('2022-07-22T21:11:51.196Z'));
    });
  });

  describe('#algorithm', () => {
    const subject = SignedCertificateTimestamp.parse(sctBuffer);

    it('returns the hash algorithm', () => {
      expect(subject.algorithm).toEqual('sha256');
    });
  });

  describe('#verify', () => {
    // Real pre-certificate used to generate the SCT
    const preCert = Buffer.from(
      'c355ee53d69e68aade04e5c6cc202cfac11fbcaa67e9a2ba7a64ced2aec8ccd000019b30820197a0030201020214466f689fbcc3be13e63ddbd14a277c41cd56d271300a06082a8648ce3d040303303731153013060355040a130c73696773746f72652e646576311e301c0603550403131573696773746f72652d696e7465726d656469617465301e170d3232303732323231313135315a170d3232303732323231323135315a30003059301306072a8648ce3d020106082a8648ce3d0301070342000459f2ab2bc2b2f9db98e711207b1c61d9f852fba456c40a1dcdd690de9ef9c2fba6133a565ccca76afdeea6352a1b0dbcf993e74e901892bca4ff3977a4a45410a381b73081b4300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070303301d0603551d0e041604141ce0136e2e5cdf1b097582a9326905ffc40f557f301f0603551d23041830168014dfd3e9cf56241196f9a8d8e92855a2c62e18643f301f0603551d110101ff041530138111627269616e40646568616d65722e636f6d302c060a2b0601040183bf300101041e68747470733a2f2f6769746875622e636f6d2f6c6f67696e2f6f61757468',
      'hex'
    );

    const subject = SignedCertificateTimestamp.parse(sctBuffer);

    describe('when no key is found for the log', () => {
      it('throws an error', () => {
        expect(() => subject.verify(preCert, [])).toThrow(
          /No key found for log/
        );
      });
    });

    describe('when the key for the log is available', () => {
      // Real key used to sign the SCT
      const ctfe =
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==';

      const ctl = {
        baseUrl: '',
        hashAlgorithm: 'HASH_ALGORITHM_UNSPECIFIED',
        publicKey: {
          rawBytes: ctfe,
          keyDetails: 'PKIX_ECDSA_P256_SHA_256',
        },
        logId: { keyId: Buffer.from(logID, 'hex') },
      };

      const logs: TransparencyLogInstance[] = [
        TransparencyLogInstance.fromJSON(ctl),
      ];

      describe('when the signature is valid', () => {
        it('returns true', () => {
          expect(subject.verify(preCert, logs)).toEqual(true);
        });
      });

      describe('when the signature is invalid', () => {
        const preCert = Buffer.from('deadbeaf', 'hex');

        it('returns false', () => {
          expect(subject.verify(preCert, logs)).toEqual(false);
        });
      });
    });
  });
});
