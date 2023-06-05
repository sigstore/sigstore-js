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
import { ASN1TypeError } from '../../../util/asn1/error';
import { ASN1Obj } from '../../../util/asn1/obj';

describe('ASN1Obj', () => {
  describe('parseBuffer', () => {
    describe('when parsing a primitive', () => {
      // INTEGER (2 bytes) 0x1010
      const buffer = Buffer.from('02021010', 'hex');

      it('parses a primitive', () => {
        const obj = ASN1Obj.parseBuffer(buffer);

        expect(obj).toBeInstanceOf(ASN1Obj);
        expect(obj.tag.number).toBe(2);
        expect(obj.value.toString('hex')).toBe('1010');
        expect(obj.subs).toHaveLength(0);

        expect(obj.toDER()).toEqual(buffer);
      });
    });

    describe('when parsing a constructed object', () => {
      // SEQUENCE (8 bytes)
      //   INTEGER (2 bytes) 0x1010
      //   INTEGER (2 bytes) 0x1111
      const buffer = Buffer.from('30080202101002021111', 'hex');
      it('parses a constructed object', () => {
        const obj = ASN1Obj.parseBuffer(buffer);

        expect(obj).toBeInstanceOf(ASN1Obj);
        expect(obj.tag.constructed).toBe(true);
        expect(obj.tag.number).toBe(16);
        expect(obj.value.toString('hex')).toBe('0202101002021111');
        expect(obj.subs).toHaveLength(2);

        expect(obj.subs[0].tag.constructed).toBe(false);
        expect(obj.subs[0].tag.number).toBe(2);
        expect(obj.subs[0].value.toString('hex')).toBe('1010');
        expect(obj.subs[0].subs).toHaveLength(0);

        expect(obj.subs[1].tag.constructed).toBe(false);
        expect(obj.subs[1].tag.number).toBe(2);
        expect(obj.subs[1].value.toString('hex')).toBe('1111');
        expect(obj.subs[1].subs).toHaveLength(0);
      });
    });

    describe('when parsing an OCTET STREAM w/ children', () => {
      // OCTET STRING (8 bytes)
      //   INTEGER (2 bytes) 0x1010
      //   INTEGER (2 bytes) 0x1010
      const buffer = Buffer.from('04080202101002021111', 'hex');
      it('parses the object', () => {
        const obj = ASN1Obj.parseBuffer(buffer);

        expect(obj).toBeInstanceOf(ASN1Obj);
        expect(obj.tag.constructed).toBe(false);
        expect(obj.tag.number).toBe(0x04);
        expect(obj.value.toString('hex')).toBe('0202101002021111');
        expect(obj.subs).toHaveLength(2);

        expect(obj.subs[0].tag.constructed).toBe(false);
        expect(obj.subs[0].tag.number).toBe(2);
        expect(obj.subs[0].value.toString('hex')).toBe('1010');
        expect(obj.subs[0].subs).toHaveLength(0);

        expect(obj.subs[1].tag.constructed).toBe(false);
        expect(obj.subs[1].tag.number).toBe(2);
        expect(obj.subs[1].value.toString('hex')).toBe('1111');
        expect(obj.subs[1].subs).toHaveLength(0);
      });
    });

    describe('when parsing an OCTET STREAM w/o children', () => {
      describe('when the OCTET STREAM value almost looks like an embedded obj', () => {
        // OCTET STREAM looks like it could have a nested OCTET STREAM, but it
        // doesn't -- the length of the nested OCTET STREAM is too long.
        const buffer = Buffer.from('04020408', 'hex');
        it('parses the OCTET STREAM as a primitive', () => {
          const obj = ASN1Obj.parseBuffer(buffer);

          expect(obj).toBeInstanceOf(ASN1Obj);
          expect(obj.tag.constructed).toBe(false);
          expect(obj.tag.number).toBe(0x04);
          expect(obj.value.toString('hex')).toBe('0408');
          expect(obj.subs).toHaveLength(0);
        });
      });

      describe('when the OCTET STREAM value almost looks like an embedded obj', () => {
        // OCTET STREAM looks like it could have a nested OCTET STREAM, but it
        // doesn't -- the length of the nested OCTET STREAM is too short.
        const buffer = Buffer.from('0406040213013131', 'hex');
        it('parses the OCTET STREAM as a primitive', () => {
          const obj = ASN1Obj.parseBuffer(buffer);

          expect(obj).toBeInstanceOf(ASN1Obj);
          expect(obj.tag.constructed).toBe(false);
          expect(obj.tag.number).toBe(0x04);
          expect(obj.value.toString('hex')).toBe('040213013131');
          expect(obj.subs).toHaveLength(0);
        });
      });
    });
  });

  describe('#toDER', () => {
    describe('when the object is a primitive', () => {
      // INTEGER (2 bytes) 0x1010
      const buffer = Buffer.from('02021010', 'hex');
      const obj = ASN1Obj.parseBuffer(buffer);

      it('encodes properly', () => {
        expect(obj.toDER()).toStrictEqual(buffer);
      });
    });

    describe('when the object has children', () => {
      // SEQUENCE (8 bytes)
      //   INTEGER (2 bytes) 0x1010
      //   INTEGER (2 bytes) 0x1111
      const buffer = Buffer.from('30080202101002021111', 'hex');
      const obj = ASN1Obj.parseBuffer(buffer);

      it('encodes properly', () => {
        expect(obj.toDER()).toStrictEqual(buffer);
      });

      describe('when the object is mutated', () => {
        const obj = ASN1Obj.parseBuffer(buffer);

        it('encodes properly', () => {
          obj.subs.splice(0, 1);
          expect(obj.toDER()).toStrictEqual(Buffer.from('300402021111', 'hex'));
        });
      });
    });
  });

  describe('#toBoolean', () => {
    describe('when the object is a BOOLEAN', () => {
      describe('when the value is 0x00', () => {
        // BOOLEAN (1 byte) 0x00
        const buffer = Buffer.from('010100', 'hex');
        it('returns false', () => {
          const obj = ASN1Obj.parseBuffer(buffer);
          expect(obj.toBoolean()).toBe(false);
        });
      });

      describe('when the value is 0x01', () => {
        // BOOLEAN (1 byte) 0x01
        const buffer = Buffer.from('010101', 'hex');
        it('returns true', () => {
          const obj = ASN1Obj.parseBuffer(buffer);
          expect(obj.toBoolean()).toBe(true);
        });
      });
    });

    describe('when the object is not a BOOLEAN', () => {
      const buffer = Buffer.from('810102', 'hex');
      it('throws an error', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(() => obj.toBoolean()).toThrow(ASN1TypeError);
      });
    });
  });

  describe('#toInteger', () => {
    describe('when the object is an INTEGER', () => {
      // INTEGER (1 bytes) 0x00
      const buffer = Buffer.from('020100', 'hex');
      it('returns the parsed integer', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(obj.toInteger()).toBe(BigInt(0));
      });
    });

    describe('when the object is NOT an INTEGER', () => {
      const buffer = Buffer.from('820100', 'hex');
      it('throws an error', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(() => obj.toInteger()).toThrow(ASN1TypeError);
      });
    });
  });

  describe('#toOID', () => {
    describe('when the object is an OBJECT IDENTIFIER', () => {
      // OBJECT IDENTIFIER (1 byte) 0x82
      const buffer = Buffer.from('060182', 'hex');
      it('returns parsed OID', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(obj.toOID()).toBe('3.10');
      });
    });

    describe('when the object is NOT an OBJECT IDENTIFIER', () => {
      const buffer = Buffer.from('020100', 'hex');
      it('throws an error', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(() => obj.toOID()).toThrow(ASN1TypeError);
      });
    });
  });

  describe('#toDate', () => {
    describe('when the object is a UTCTime', () => {
      // UTCTime (13 bytes) 0x3232313132323131313131315A
      const buffer = Buffer.from('170D3232313132323131313131315A', 'hex');
      it('returns the parsed date', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(obj.toDate().toISOString()).toBe('2022-11-22T11:11:11.000Z');
      });
    });

    describe('when the object is a GeneralizedTime', () => {
      // GeneralizedTime (15 bytes) 0x32303232313132323131313131315A
      const buffer = Buffer.from('180F32303232313132323131313131315A', 'hex');
      it('returns the parsed date', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(obj.toDate().toISOString()).toBe('2022-11-22T11:11:11.000Z');
      });
    });

    describe('when the object is NOT an UTCTime or GeneralizedTime', () => {
      const buffer = Buffer.from('020100', 'hex');
      it('throws an error', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(() => obj.toDate()).toThrow(ASN1TypeError);
      });
    });
  });

  describe('#toBitString', () => {
    describe('when the object is a BITSTRING', () => {
      // BITSTRING (2 bytes) 0x00F0
      const buffer = Buffer.from('030200F0', 'hex');
      it('returns the parsed bit string', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(obj.toBitString()).toEqual([1, 1, 1, 1, 0, 0, 0, 0]);
      });
    });

    describe('when the object is NOT a BITSTRING', () => {
      const buffer = Buffer.from('020100', 'hex');
      it('throws an error', () => {
        const obj = ASN1Obj.parseBuffer(buffer);
        expect(() => obj.toBitString()).toThrow(ASN1TypeError);
      });
    });
  });
});
