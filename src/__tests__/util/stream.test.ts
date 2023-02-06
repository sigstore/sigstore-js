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
import { ByteStream } from '../../util/stream';

describe('ByteStream', () => {
  const buf = Buffer.from([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  ]);
  const subject = new ByteStream(buf);

  beforeEach(() => {
    subject.seek(0);
  });

  describe('constructor', () => {
    it('should create a new ByteStream', () => {
      expect(subject).toBeTruthy();
      expect(subject.position).toEqual(0);
    });
  });

  describe('#length', () => {
    it('should return the length of the buffer', () => {
      expect(subject.length).toEqual(buf.length);
    });
  });

  describe('#seek', () => {
    it('should set the position', () => {
      subject.seek(5);
      expect(subject.position).toEqual(5);
    });
  });

  describe('#getBlock', () => {
    describe('when the block size is 0', () => {
      it('should return an empty buffer', () => {
        expect(subject.getBlock(0)).toHaveLength(0);
      });
    });
  });

  describe('#getUint8', () => {
    describe('when the position is less than the length', () => {
      it('should return the next byte and increment cursor', () => {
        expect(subject.getUint8()).toEqual(buf[0]);
        expect(subject.position).toEqual(1);
        expect(subject.getUint8()).toEqual(buf[1]);
        expect(subject.position).toEqual(2);
      });
    });

    describe('when the position is greater than the length', () => {
      beforeEach(() => {
        subject.seek(10);
      });

      it('should throw an error', () => {
        expect(() => subject.getUint8()).toThrowError(
          'request past end of buffer'
        );
      });
    });
  });

  describe('#getUint16', () => {
    describe('when the position is less than the length', () => {
      it('should return the next uint16 and increment cursor', () => {
        expect(subject.getUint16()).toEqual(0x0001);
        expect(subject.position).toEqual(2);
        expect(subject.getUint16()).toEqual(0x0203);
        expect(subject.position).toEqual(4);
      });
    });

    describe('when the position is greater than the length', () => {
      beforeEach(() => {
        subject.seek(10);
      });

      it('should throw an error', () => {
        expect(() => subject.getUint16()).toThrowError(
          'request past end of buffer'
        );
      });
    });
  });

  describe('#slice', () => {
    describe('when the length is less than the buffer length', () => {
      it('should return a slice of the buffer', () => {
        expect(subject.slice(0, 5)).toEqual(buf.subarray(0, 5));
      });
    });

    describe('when the length is greater than the buffer length', () => {
      it('should throw an error', () => {
        expect(() => subject.slice(0, 11)).toThrowError(
          'request past end of buffer'
        );
      });
    });
  });

  describe('#appendChar', () => {
    const subject = new ByteStream();

    it('should append a character to the buffer', () => {
      subject.appendChar(0x0a);
      expect(subject.buffer).toEqual(Buffer.from([0x0a]));
      expect(subject.position).toEqual(1);
    });
  });

  describe('#appendUint16', () => {
    const subject = new ByteStream();

    it('should append a uint16 to the buffer', () => {
      subject.appendUint16(0x0a0b);
      expect(subject.buffer).toEqual(Buffer.from([0x0a, 0x0b]));
      expect(subject.position).toEqual(2);
    });
  });

  describe('#appendUint24', () => {
    const subject = new ByteStream();

    it('should append a uint24 to the buffer', () => {
      subject.appendUint24(0x0a0b0c);
      expect(subject.buffer).toEqual(Buffer.from([0x0a, 0x0b, 0x0c]));
      expect(subject.position).toEqual(3);
    });
  });

  describe('appendView', () => {
    const subject = new ByteStream();

    it('should append a view to the buffer', () => {
      subject.appendView(buf);
      expect(subject.buffer).toEqual(buf);
      expect(subject.position).toEqual(buf.length);
    });
  });
});
