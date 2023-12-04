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
import { ByteStream } from '../stream';
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
  readonly value: Buffer;

  constructor(tag: ASN1Tag, value: Buffer, subs: ASN1Obj[]) {
    this.tag = tag;
    this.value = value;
    this.subs = subs;
  }

  // Constructs an ASN.1 object from a Buffer of DER-encoded bytes.
  public static parseBuffer(buf: Buffer): ASN1Obj {
    return parseStream(new ByteStream(buf));
  }

  public toDER(): Buffer {
    const valueStream = new ByteStream();

    if (this.subs.length > 0) {
      for (const sub of this.subs) {
        valueStream.appendView(sub.toDER());
      }
    } else {
      valueStream.appendView(this.value);
    }

    const value = valueStream.buffer;

    // Concat tag/length/value
    const obj = new ByteStream();
    obj.appendChar(this.tag.toDER());
    obj.appendView(encodeLength(value.length));
    obj.appendView(value);

    return obj.buffer;
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
  // Parse tag, length, and value from stream
  const tag = new ASN1Tag(stream.getUint8());
  const len = decodeLength(stream);
  const value = stream.slice(stream.position, len);

  const start = stream.position;

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
    stream.seek(start + len);
  }

  return new ASN1Obj(tag, value, subs);
}

function collectSubs(stream: ByteStream, len: number): ASN1Obj[] {
  // Calculate end of object content
  const end = stream.position + len;

  // Make sure there are enough bytes left in the stream. This should never
  // happen, cause it'll get caught when the stream is sliced in parseStream.
  // Leaving as an extra check just in case.
  /* istanbul ignore if */
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
