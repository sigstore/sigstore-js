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
import { ASN1ParseError } from '../../asn1/error';
import { ASN1Obj } from '../../asn1/obj';
import { encodeLength } from '../../asn1/length';

// Collection of malformed/adversarial DER inputs that the parser must reject
// rather than crash on or silently mis-parse.
describe('ASN1Obj.parseBuffer with malformed input', () => {
  describe('deeply nested structures', () => {
    // Wrap an empty SEQUENCE in `levels` additional SEQUENCEs.
    function nestedSequence(levels: number): Buffer {
      let buf = Buffer.from([0x30, 0x00]); // empty SEQUENCE
      for (let i = 0; i < levels; i++) {
        buf = Buffer.concat([
          Buffer.from([0x30]),
          encodeLength(buf.length),
          buf,
        ]);
      }
      return buf;
    }

    describe('when nesting is within the limit', () => {
      it('parses successfully', () => {
        expect(() => ASN1Obj.parseBuffer(nestedSequence(50))).not.toThrow();
      });
    });

    describe('when nesting exceeds the maximum depth', () => {
      it('throws an error', () => {
        expect(() => ASN1Obj.parseBuffer(nestedSequence(200))).toThrow(
          ASN1ParseError
        );
        expect(() => ASN1Obj.parseBuffer(nestedSequence(200))).toThrow(
          'maximum nesting depth exceeded'
        );
      });
    });
  });

  describe('trailing data after the top-level object', () => {
    it('throws an error', () => {
      // BOOLEAN (false) followed by an extra trailing byte
      const buffer = Buffer.from('01010000', 'hex');
      expect(() => ASN1Obj.parseBuffer(buffer)).toThrow(ASN1ParseError);
      expect(() => ASN1Obj.parseBuffer(buffer)).toThrow('invalid trailing data');
    });
  });

  describe('non-minimal length encoding', () => {
    it('throws an error', () => {
      // SEQUENCE with a long-form length encoding a value < 128
      const buffer = Buffer.from('30810100', 'hex');
      expect(() => ASN1Obj.parseBuffer(buffer)).toThrow(
        'non-minimal length encoding'
      );
    });
  });

  describe('non-canonical boolean', () => {
    it('throws an error when accessed as a boolean', () => {
      // BOOLEAN with a non-canonical value (0x01 instead of 0xff)
      const obj = ASN1Obj.parseBuffer(Buffer.from('010101', 'hex'));
      expect(() => obj.toBoolean()).toThrow('invalid boolean');
    });
  });

  describe('oversized OID arc', () => {
    it('does not truncate arcs that exceed 32 bits', () => {
      // OID with an arc value of 2^35 + 10 (would truncate in 32-bit math)
      const obj = ASN1Obj.parseBuffer(
        Buffer.from('06072a81808080800a', 'hex')
      );
      expect(obj.toOID()).toEqual('1.2.34359738378');
    });
  });

  describe('bit string with invalid unused-bits count', () => {
    it('throws an error when accessed as a bit string', () => {
      // BIT STRING whose first byte (unused bits) is 8 (must be 0-7)
      const obj = ASN1Obj.parseBuffer(Buffer.from('03020857', 'hex'));
      expect(() => obj.toBitString()).toThrow('invalid bit string');
    });
  });
});
