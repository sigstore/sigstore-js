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
import { ASN1Tag } from '../../asn1/tag';

describe('ASN1Tag', () => {
  describe('when the tag is in the universal tag class', () => {
    describe('when the tag is primitive ', () => {
      it('should parse a tag', () => {
        const tag = new ASN1Tag(0x02);
        expect(tag.number).toEqual(0x02);
        expect(tag.class).toEqual(0);
        expect(tag.isUniversal()).toEqual(true);
        expect(tag.constructed).toEqual(false);
      });
    });

    describe('when the tag is constructed ', () => {
      it('should parse a tag', () => {
        const tag = new ASN1Tag(0x30);
        expect(tag.number).toEqual(0x10);
        expect(tag.class).toEqual(0);
        expect(tag.isUniversal()).toEqual(true);
        expect(tag.constructed).toEqual(true);
      });
    });
  });

  describe('when the tag is in the context-specifc tag class', () => {
    describe('when the tag is constructed ', () => {
      it('should parse a tag', () => {
        const tag = new ASN1Tag(0xa3);
        expect(tag.number).toEqual(0x03);
        expect(tag.class).toEqual(0x02);
        expect(tag.isUniversal()).toEqual(false);
        expect(tag.constructed).toEqual(true);
      });
    });
  });

  describe('when the tag is long form', () => {
    it('should throw an error', () => {
      expect(() => new ASN1Tag(0x1f)).toThrowError(ASN1ParseError);
    });
  });

  describe('when the tag is the null tag', () => {
    it('should throw an error', () => {
      expect(() => new ASN1Tag(0x20)).toThrowError(ASN1ParseError);
    });
  });

  describe('#isContextSpecific', () => {
    describe('when the tag is context-specific', () => {
      const tag = new ASN1Tag(0xa3);

      describe('when a tag number filter is supplied', () => {
        describe('when the tag number matches', () => {
          it('returns true', () => {
            expect(tag.isContextSpecific(0x03)).toEqual(true);
          });
        });

        describe('when the tag number does NOT match', () => {
          it('returns false', () => {
            expect(tag.isContextSpecific(0x06)).toEqual(false);
            expect(tag.isContextSpecific(0x00)).toEqual(false);
          });
        });
      });

      describe('when a tag number filter is NOT supplied', () => {
        it('should return true', () => {
          expect(tag.isContextSpecific()).toEqual(true);
        });
      });
    });

    describe('when the tag is not context-specific', () => {
      it('should return false', () => {
        const tag = new ASN1Tag(0x02);
        expect(tag.isContextSpecific()).toEqual(false);
        expect(tag.isContextSpecific(0x02)).toEqual(false);
      });
    });
  });

  describe('#isBoolean', () => {
    describe('when the tag is a boolean', () => {
      it('should return true', () => {
        const tag = new ASN1Tag(0x01);
        expect(tag.isBoolean()).toEqual(true);
      });
    });

    describe('when the tag is not a boolean', () => {
      it('should return false', () => {
        let tag = new ASN1Tag(0x02);
        expect(tag.isBoolean()).toEqual(false);

        tag = new ASN1Tag(0x81);
        expect(tag.isBoolean()).toEqual(false);
      });
    });
  });

  describe('#isInteger', () => {
    describe('when the tag is an integer', () => {
      it('should return true', () => {
        const tag = new ASN1Tag(0x02);
        expect(tag.isInteger()).toEqual(true);
      });
    });

    describe('when the tag is not an integer', () => {
      it('should return false', () => {
        let tag = new ASN1Tag(0x01);
        expect(tag.isInteger()).toEqual(false);

        tag = new ASN1Tag(0x82);
        expect(tag.isInteger()).toEqual(false);
      });
    });
  });

  describe('#isBitString', () => {
    describe('when the tag is a bit string', () => {
      it('should return true', () => {
        const tag = new ASN1Tag(0x03);
        expect(tag.isBitString()).toEqual(true);
      });
    });

    describe('when the tag is not a bit string', () => {
      it('should return false', () => {
        let tag = new ASN1Tag(0x02);
        expect(tag.isBitString()).toEqual(false);

        tag = new ASN1Tag(0x83);
        expect(tag.isBitString()).toEqual(false);
      });
    });
  });

  describe('#isOctetString', () => {
    describe('when the tag is an octet string', () => {
      it('should return true', () => {
        const tag = new ASN1Tag(0x04);
        expect(tag.isOctetString()).toEqual(true);
      });
    });

    describe('when the tag is not an octet string', () => {
      it('should return false', () => {
        let tag = new ASN1Tag(0x02);
        expect(tag.isOctetString()).toEqual(false);

        tag = new ASN1Tag(0x84);
        expect(tag.isOctetString()).toEqual(false);
      });
    });
  });

  describe('#isOID', () => {
    describe('when the tag is an OID', () => {
      it('should return true', () => {
        const tag = new ASN1Tag(0x06);
        expect(tag.isOID()).toEqual(true);
      });
    });

    describe('when the tag is not an OID', () => {
      it('should return false', () => {
        let tag = new ASN1Tag(0x02);
        expect(tag.isOID()).toEqual(false);

        tag = new ASN1Tag(0x86);
        expect(tag.isOID()).toEqual(false);
      });
    });
  });

  describe('#isUTCTime', () => {
    describe('when the tag is a UTCTime', () => {
      it('should return true', () => {
        const tag = new ASN1Tag(0x17);
        expect(tag.isUTCTime()).toEqual(true);
      });
    });

    describe('when the tag is not a UTCTime', () => {
      it('should return false', () => {
        let tag = new ASN1Tag(0x02);
        expect(tag.isUTCTime()).toEqual(false);

        tag = new ASN1Tag(0x57);
        expect(tag.isUTCTime()).toEqual(false);
      });
    });
  });

  describe('#isGeneralizedTime', () => {
    describe('when the tag is a GeneralizedTime', () => {
      it('should return true', () => {
        const tag = new ASN1Tag(0x18);
        expect(tag.isGeneralizedTime()).toEqual(true);
      });
    });

    describe('when the tag is not a UTCTime', () => {
      it('should return false', () => {
        let tag = new ASN1Tag(0x02);
        expect(tag.isGeneralizedTime()).toEqual(false);

        tag = new ASN1Tag(0x58);
        expect(tag.isGeneralizedTime()).toEqual(false);
      });
    });
  });

  describe('#toDER', () => {
    it('should return the DER encoding of the tag', () => {
      expect(new ASN1Tag(0x02).toDER()).toEqual(0x02);
      expect(new ASN1Tag(0x30).toDER()).toEqual(0x30);
      expect(new ASN1Tag(0xa3).toDER()).toEqual(0xa3);
    });
  });
});
