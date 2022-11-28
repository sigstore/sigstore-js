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

  describe('length', () => {
    it('should return the length of the buffer', () => {
      expect(subject.length).toEqual(buf.length);
    });
  });

  describe('seek', () => {
    it('should set the position', () => {
      subject.seek(5);
      expect(subject.position).toEqual(5);
    });
  });

  describe('get', () => {
    describe('when the position is less than the length', () => {
      it('should return the next byte and increment cursor', () => {
        expect(subject.get()).toEqual(buf[0]);
        expect(subject.position).toEqual(1);
        expect(subject.get()).toEqual(buf[1]);
        expect(subject.position).toEqual(2);
      });
    });

    describe('when the position is greater than the length', () => {
      beforeEach(() => {
        subject.seek(10);
      });

      it('should throw an error', () => {
        expect(() => subject.get()).toThrowError('request past end of buffer');
      });
    });
  });

  describe('slice', () => {
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
});
