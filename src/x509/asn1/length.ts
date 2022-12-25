// Decodes the length of an ANS.1 element.

import { ByteStream } from '../../util/stream';
import { ASN1ParseError } from './error';

// Decodes the length of a DER-encoded ANS.1 element from the supplied stream.
// https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-length-and-value-bytes
export function decodeLength(stream: ByteStream): number {
  const buf = stream.getUint8();

  // If the most significant bit is UNSET the length is just the value of the
  // byte.
  if ((buf & 0x80) === 0x00) {
    return buf;
  }

  // Otherwise, the lower 7 bits of the first byte indicate the number of bytes
  // that follow to encode the length.
  const byteCount = buf & 0x7f;

  // Ensure the encoded length can safely fit in a JS number.
  if (byteCount > 6) {
    throw new ASN1ParseError('length exceeds 6 byte limit');
  }

  // Iterate over the bytes that encode the length.
  let len = 0;
  for (let i = 0; i < byteCount; i++) {
    len = len * 256 + stream.getUint8();
  }

  // This is a valid ASN.1 length encoding, but we don't support it.
  if (len === 0) {
    throw new ASN1ParseError('indefinite length encoding not supported');
  }

  return len;
}

// Translates the supplied value to a DER-encoded length.
export function encodeLength(len: number): Buffer {
  if (len < 128) {
    return Buffer.from([len]);
  }

  // Bitwise operations on large numbers are not supported in JS, so we need to
  // use BigInts.
  let val = BigInt(len);
  const bytes = [];

  while (val > 0n) {
    bytes.unshift(Number(val & 255n));
    val = val >> 8n;
  }

  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
