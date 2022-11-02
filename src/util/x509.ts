import net from 'net';
import tls, { PeerCertificate } from 'tls';
import { fromDER } from './pem';

interface x509Certificate {
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
}

// Returns the parsed form of an X.509 certificate. Until we have a better
// solution, this is a very simple implementation that only parses the
// serial number and validity period. We're taking advantage of the
// fact that the TLSSocket class exposes a getPeerCertificate() method which
// returns basic information about its associated certificate.
export function parseCertificate(cert: string | Buffer): x509Certificate {
  const pem = typeof cert === 'string' ? cert : fromDER(cert);

  const secureContext = tls.createSecureContext({ cert: pem });
  const secureSocket = new tls.TLSSocket(new net.Socket(), { secureContext });
  const certFields = secureSocket.getCertificate() as PeerCertificate;
  secureSocket.destroy();

  return {
    serialNumber: certFields.serialNumber,
    validFrom: new Date(certFields.valid_from),
    validTo: new Date(certFields.valid_to),
  };
}
