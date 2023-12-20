import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { ESSCertIDv2 } from './ess-cert-id';

describe('ESSCertIDv2', () => {
  describe('constructor', () => {
    describe('when no parameters are provided', () => {
      it('should set the certHash and issuerSerial to empty buffers', () => {
        const essCertIDv2 = new ESSCertIDv2();
        expect(essCertIDv2).toBeDefined();
      });
    });

    describe('when parameters are provided', () => {
      it('should set the certHash and issuerSerial', () => {
        const certHash = new asn1js.OctetString({
          valueHex: new ArrayBuffer(0),
        });
        const issuerSerial = new pkijs.IssuerSerial({
          issuer: new pkijs.GeneralNames({
            names: [
              new pkijs.GeneralName({ type: 4, value: new ArrayBuffer(0) }),
            ],
          }),
          serialNumber: new asn1js.Integer({ value: 888 }),
        });
        const essCertIDv2 = new ESSCertIDv2({ certHash, issuerSerial });

        expect(essCertIDv2.certHash).toBe(certHash);
        expect(essCertIDv2.issuerSerial).toBe(issuerSerial);
      });
    });
  });
});
