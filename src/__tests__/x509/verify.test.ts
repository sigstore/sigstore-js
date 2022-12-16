import { pem } from '../../util';
import { x509Certificate } from '../../x509/cert';
import { CertificateChainVerifier } from '../../x509/verify';
import { certificates } from '../__fixtures__/certs';

describe('CertificateChainVerifier', () => {
  describe('debugging', () => {
    const rootCert = x509Certificate.fromDER(
      pem.toDER(certificates.root),
      'root'
    );
    const intCert = x509Certificate.fromDER(
      pem.toDER(certificates.intermediate),
      'int'
    );
    const leafCert = x509Certificate.fromDER(
      pem.toDER(certificates.leaf),
      'leaf'
    );
    it('does things', () => {
      const subject = new CertificateChainVerifier({
        trustedCerts: [intCert, rootCert],
        certs: [rootCert, intCert, leafCert],
        checkDate: new Date('2022-12-08T16:22:00.000Z'),
      });

      subject.verify();
    });
  });
});
