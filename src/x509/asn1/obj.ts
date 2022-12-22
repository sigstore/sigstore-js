import { ByteStream } from '../../util/stream';
import { ASN1ParseError, ASN1TypeError } from './error';
import { decodeLength, encodeLength } from './length';
import {
  parseBitString,
  parseBoolean,
  parseInteger,
  parseOID,
  parseTime,
} from './parse';
import { ASN1Tag } from './tag';

export class ASN1Obj {
  readonly tag: ASN1Tag;
  readonly subs: ASN1Obj[];
  private buf: Buffer;
  private headerLength: number;

  constructor(
    tag: ASN1Tag,
    headerLength: number,
    buf: Buffer,
    subs: ASN1Obj[]
  ) {
    this.tag = tag;
    this.headerLength = headerLength;
    this.buf = buf;
    this.subs = subs;
  }

  // Constructs an ASN.1 object from a Buffer of DER-encoded bytes.
  public static parseBuffer(buf: Buffer): ASN1Obj {
    return parseStream(new ByteStream(buf));
  }

  // Returns the raw bytes of the ASN.1 object's value. For constructed objects,
  // this is the concatenation of the raw bytes of the values of its children.
  // For primitive objects, this is the raw bytes of the object's value.
  // Use the various to* methods to parse the value into a specific type.
  get value(): Buffer {
    return this.buf.subarray(this.headerLength);
  }

  // Returns the raw bytes of the entire ASN.1 object (including tag, length,
  // and value)
  get raw(): Buffer {
    return this.buf;
  }

  public toDER(): Buffer {
    let value: Buffer;

    if (this.subs.length > 0) {
      value = Buffer.alloc(0);
      for (const sub of this.subs) {
        value = Buffer.concat([value, sub.toDER()]);
      }
    } else {
      value = this.value;
    }

    const tag = Buffer.from([this.tag.toDER()]);
    const len = encodeLength(value.length);

    return Buffer.concat([tag, len, value]);
  }

  /////////////////////////////////////////////////////////////////////////////
  // Convenience methods for parsing ASN.1 primitives into JS types

  // Returns the ASN.1 object's value as a boolean. Throws an error if the
  // object is not a boolean.
  public toBoolean(): boolean {
    if (!this.tag.isBoolean()) {
      throw new ASN1TypeError('not a boolean');
    }

    return parseBoolean(this.value);
  }

  // Returns the ASN.1 object's value as a BigInt. Throws an error if the
  // object is not an integer.
  public toInteger(): bigint {
    if (!this.tag.isInteger()) {
      throw new ASN1TypeError('not an integer');
    }

    return parseInteger(this.value);
  }

  // Returns the ASN.1 object's value as an OID string. Throws an error if the
  // object is not an OID.
  public toOID(): string {
    if (!this.tag.isOID()) {
      throw new ASN1TypeError('not an OID');
    }

    return parseOID(this.value);
  }

  // Returns the ASN.1 object's value as a Date. Throws an error if the object
  // is not either a UTCTime or a GeneralizedTime.
  public toDate(): Date {
    switch (true) {
      case this.tag.isUTCTime():
        return parseTime(this.value, true);
      case this.tag.isGeneralizedTime():
        return parseTime(this.value, false);
      default:
        throw new ASN1TypeError('not a date');
    }
  }

  // Returns the ASN.1 object's value as a number[] where each number is the
  // value of a bit in the bit string. Throws an error if the object is not a
  // bit string.
  public toBitString(): number[] {
    if (!this.tag.isBitString()) {
      throw new ASN1TypeError('not a bit string');
    }

    return parseBitString(this.value);
  }
}

/////////////////////////////////////////////////////////////////////////////
// Internal stream parsing functions

function parseStream(stream: ByteStream): ASN1Obj {
  // Capture current stream position so we know where this object starts
  const startPos = stream.position;

  // Parse tag and length from stream
  const tag = new ASN1Tag(stream.get());
  const len = decodeLength(stream);

  // Calculate length of header (tag + length)
  const header = stream.position - startPos;

  let subs: ASN1Obj[] = [];
  // If the object is constructed, parse its children. Sometimes, children
  // are embedded in OCTESTRING objects, so we need to check those
  // for children as well.
  if (tag.constructed) {
    subs = collectSubs(stream, len);
  } else if (tag.isOctetString()) {
    // Attempt to parse children of OCTETSTRING objects. If anything fails,
    // assume the object is not constructed and treat as primitive.
    try {
      subs = collectSubs(stream, len);
    } catch (e) {
      // Fail silently and treat as primitive
    }
  }

  // If there are no children, move stream cursor to the end of the object
  if (subs.length === 0) {
    stream.seek(startPos + header + len);
  }

  // Capture the raw bytes of the object (including tag, length, and value)
  const buf = stream.slice(startPos, header + len);

  return new ASN1Obj(tag, header, buf, subs);
}

function collectSubs(stream: ByteStream, len: number): ASN1Obj[] {
  // Calculate end of object content
  const end = stream.position + len;

  // Make sure there are enough bytes left in the stream
  if (end > stream.length) {
    throw new ASN1ParseError('invalid length');
  }

  // Parse all children
  const subs: ASN1Obj[] = [];
  while (stream.position < end) {
    subs.push(parseStream(stream));
  }

  // When we're done parsing children, we should be at the end of the object
  if (stream.position !== end) {
    throw new ASN1ParseError('invalid length');
  }

  return subs;
}
