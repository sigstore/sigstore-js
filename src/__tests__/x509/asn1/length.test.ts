import { ByteStream } from '../../../util/stream';
import { decodeLength } from '../../../x509/asn1/length';

describe('decodeLength', () => {
  describe('when the encoded length is less than 128', () => {
    const stream = streamFromBytes([0x10]);
    it('should return the length', () => {
      expect(decodeLength(stream)).toEqual(16);
    });
  });

  describe('when the encoded length is equal to 128', () => {
    const stream = streamFromBytes([0x81, 0x80]);
    it('should return the length', () => {
      expect(decodeLength(stream)).toEqual(128);
    });
  });

  describe('when the encoded length is the max value', () => {
    const stream = streamFromBytes([0x86, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    it('should return the length', () => {
      expect(decodeLength(stream)).toEqual(281474976710655);
    });
  });

  describe('when the encoded length requires more than 6 bytes', () => {
    const stream = streamFromBytes([
      0x87, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    it('throws an error', () => {
      expect(() => decodeLength(stream)).toThrowError(
        'length exceeds 6 byte limit'
      );
    });
  });

  describe('when the encoded length is indefinite', () => {
    const stream = streamFromBytes([0x80]);
    it('throws an error', () => {
      expect(() => decodeLength(stream)).toThrowError(
        'indefinite length encoding not supported'
      );
    });
  });
});

function streamFromBytes(bytes: number[]): ByteStream {
  return new ByteStream(Buffer.from(bytes));
}
