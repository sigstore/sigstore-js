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
  public get(): number {
    const pos = this.pos++;

    if (pos >= this.length) {
      throw new StreamError('request past end of buffer');
    }

    return this.buf[pos];
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
