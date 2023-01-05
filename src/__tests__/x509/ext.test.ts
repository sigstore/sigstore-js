import { ASN1Obj } from '../../x509/asn1/obj';
import { x509SCTExtension } from '../../x509/ext';
import { SignedCertificateTimestamp } from '../../x509/sct';

describe('x509SCTExtension', () => {
  describe('constructor', () => {
    const sctExtension = Buffer.from(
      '3012060A2B06010401D679020402040404020000',
      'hex'
    );
    const obj = ASN1Obj.parseBuffer(sctExtension);

    it('parses the extension', () => {
      const subject = new x509SCTExtension(obj);
      expect(subject.critical).toBe(false);
      expect(subject.oid).toBe('1.3.6.1.4.1.11129.2.4.2');
    });
  });

  describe('#signedCertificateTimestamps', () => {
    describe('when there are no SCTs in the extension', () => {
      // Extension w/ zero-length array of SCTs
      const sctExtension = Buffer.from(
        '3012060A2B06010401D679020402040404020000',
        'hex'
      );
      const subject = new x509SCTExtension(ASN1Obj.parseBuffer(sctExtension));

      it('returns an empty array', () => {
        const scts = subject.signedCertificateTimestamps;
        expect(scts).toBeDefined();
        expect(scts).toHaveLength(0);
      });
    });

    describe('when there are SCTs in the extension', () => {
      const sctExtension = Buffer.from(
        '3043060A2B06010401D679020402043504330031002F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'hex'
      );
      const subject = new x509SCTExtension(ASN1Obj.parseBuffer(sctExtension));

      it('returns an array of SCTs', () => {
        const scts = subject.signedCertificateTimestamps;
        expect(scts).toBeDefined();
        expect(scts).toHaveLength(1);
        expect(scts[0]).toBeInstanceOf(SignedCertificateTimestamp);
      });
    });

    describe('when the stated length of the SCT list does not match the data ', () => {
      // Extension where length of SCT list is mismatched with the length of the constituent SCTs
      const sctExtension = Buffer.from(
        //                                   |--| Should be 0x0031 for a valid SCT extension
        '3043060A2B06010401D67902040204350433002F002F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        'hex'
      );
      const subject = new x509SCTExtension(ASN1Obj.parseBuffer(sctExtension));

      it('throws an error', () => {
        expect(() => {
          subject.signedCertificateTimestamps;
        }).toThrow(/length does not match/);
      });
    });
  });
});
