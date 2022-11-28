export class ByteStream {
  private static BLOCK_SIZE = 1024;

  private buf: ArrayBuffer;
  private view: Buffer;
  private start = 0;

  constructor(buffer?: ArrayBuffer) {
    if (buffer) {
      this.buf = buffer;
      this.view = Buffer.from(buffer);
    } else {
      this.buf = new ArrayBuffer(0);
      this.view = Buffer.from(this.buf);
    }
  }

  get buffer(): Buffer {
    return this.view.subarray(0, this.start);
  }

  get position(): number {
    return this.start;
  }

  public appendChar(char: number) {
    this.ensureCapacity(1);
    this.view[this.start] = char;
    this.start += 1;
  }

  public appendUint16(num: number) {
    this.ensureCapacity(2);

    const value = new Uint16Array([num]);
    const view = new Uint8Array(value.buffer);

    this.view[this.start] = view[1];
    this.view[this.start + 1] = view[0];
    this.start += 2;
  }

  public appendUint24(num: number) {
    this.ensureCapacity(3);

    const value = new Uint32Array([num]);
    const view = new Uint8Array(value.buffer);

    this.view[this.start] = view[2];
    this.view[this.start + 1] = view[1];
    this.view[this.start + 2] = view[0];
    this.start += 3;
  }

  public appendView(view: Uint8Array) {
    this.ensureCapacity(view.length);
    this.view.set(view, this.start);
    this.start += view.length;
  }

  public getBlock(size: number): Buffer {
    if (size <= 0) {
      return Buffer.alloc(0);
    }

    if (this.start + size > this.view.length) {
      throw new Error('Unexpected end of stream');
      //   size = this.view.length - this.start;
    }

    const result = this.view.subarray(this.start, this.start + size);
    this.start += size;

    return result;
  }

  public getUint8(): number {
    return this.getBlock(1)[0];
  }

  public getUint16(): number {
    const block = this.getBlock(2);

    if (block.length < 2) {
      return 0;
    }

    return (block[0] << 8) | block[1];
  }

  private ensureCapacity(size: number) {
    if (this.start + size > this.view.byteLength) {
      const blockSize =
        ByteStream.BLOCK_SIZE + (size > ByteStream.BLOCK_SIZE ? size : 0);
      this.realloc(this.view.byteLength + blockSize);
    }
  }

  private realloc(size: number) {
    const newArray = new ArrayBuffer(size);
    const newView = Buffer.from(newArray);

    // Copy the old buffer into the new one
    if (size > this.view.length) {
      newView.set(this.view);
    } else {
      newView.set(this.view.subarray(0, size));
    }

    this.buf = newArray;
    this.view = newView;
  }
}
