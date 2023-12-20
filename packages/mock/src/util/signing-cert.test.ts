import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { ESSCertIDv2 } from './ess-cert-id';
import { SigningCertificateV2 } from './signing-cert';

describe('SigningCertificateV2', () => {
  describe('constructor', () => {
    describe('when no parameters are provided', () => {
      it('should set the certs to an empty array', () => {
        const signingCertificateV2 = new SigningCertificateV2();
        expect(signingCertificateV2).toBeDefined();
      });
    });

    describe('when parameters are provided', () => {
      it('should set the certs', () => {
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
        const signingCertificateV2 = new SigningCertificateV2({
          certs: [essCertIDv2],
        });

        expect(signingCertificateV2.certs).toHaveLength(1);
        expect(signingCertificateV2.certs[0]).toBe(essCertIDv2);
      });
    });
  });
});
