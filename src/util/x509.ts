import net from 'net';
import tls, { PeerCertificate } from 'tls';

interface Certificate {
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
}

export function parseX509Certificate(pem: string): Certificate {
  const secureContext = tls.createSecureContext({
    cert: pem,
  });

  const secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
  const certFields = secureSocket.getCertificate() as PeerCertificate;

  return {
    serialNumber: certFields.serialNumber,
    validFrom: new Date(certFields.valid_from),
    validTo: new Date(certFields.valid_to),
  };
}
