export class StreamError extends Error {}

export class ByteStream {
  private buf: Buffer;
  private pos: number;

  constructor(buf: Buffer, pos = 0) {
    this.buf = buf;
    this.pos = pos;
  }

  // Returns the current stream position
  get position(): number {
    return this.pos;
  }

  // Returns the number of bytes in the stream
  get length(): number {
    return this.buf.length;
  }

  // Resets the stream to the given postion
  public seek(pos: number): void {
    this.pos = pos;
  }

  // Returns the next byte in the stream
  public get(length: number): Buffer;
  public get(): number;
  public get(length = 1): Buffer | number {
    if (this.pos + length > this.length) {
      throw new StreamError('request past end of buffer');
    }

    let res: Buffer | number;
    if (length > 1) {
      res = this.slice(this.pos, length);
    } else {
      res = this.buf[this.pos];
    }

    this.pos += length;
    return res;
  }

  // Returns a Buffer containing the specified number of bytes starting at the
  // given start position.
  public slice(start: number, len: number): Buffer {
    const end = start + len;

    if (end > this.length) {
      throw new StreamError('request past end of buffer');
    }

    return this.buf.subarray(start, end);
  }
}
