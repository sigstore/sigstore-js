import { x509Certificate } from './cert';

interface VerifyCertificateChainOptions {
  trustedCerts: x509Certificate[];
  certs: x509Certificate[];
  checkDate?: Date;
}

export class CertificateChainVerifier {
  private certs: x509Certificate[];
  private trustedCerts: x509Certificate[];
  private checkDate: Date;

  constructor(opts: VerifyCertificateChainOptions) {
    this.certs = unique([...opts.trustedCerts, ...opts.certs]);
    this.trustedCerts = opts.trustedCerts;
    this.checkDate = opts.checkDate || new Date();
  }

  public verify(): void {
    // Construct certificate path from leaf to root
    const certificatePath = this.sort();

    // Perform validation checks on each certificate in the path
    this.checkPath(certificatePath);
  }

  private sort(): x509Certificate[] {
    const leafCert = this.certs[this.certs.length - 1];

    // Construct all possible paths from the leaf
    let paths = this.buildPaths(leafCert);

    // Filter for paths which contain a trusted certificate
    paths = paths.filter((path) =>
      path.some((cert) => this.trustedCerts.includes(cert))
    );

    if (paths.length === 0) {
      throw new Error('No valid certificate path found');
    }

    // Find the shortest of possible paths
    const path = paths.reduce((prev, curr) =>
      prev.length < curr.length ? prev : curr
    );

    // Construct chain from shortest path
    return [leafCert, ...path];
  }

  // Recursively build all possible paths from the leaf to the root
  private buildPaths(certificate: x509Certificate): x509Certificate[][] {
    const paths = [];
    const issuers = this.findIssuer(certificate);

    if (issuers.length === 0) {
      throw new Error('No valid certificate path found');
    }

    for (let i = 0; i < issuers.length; i++) {
      const issuer = issuers[i];

      // If issuer is self, add a new empty path and continue
      if (bufferEqual(issuer.tbsCertificate, certificate.tbsCertificate)) {
        paths.push([]);
        continue;
      }

      // Recursively build path for the issuer
      const subPaths = this.buildPaths(issuer);

      // Construct paths by appending the issuer to each subpath
      for (let j = 0; j < subPaths.length; j++) {
        paths.push([issuer, ...subPaths[j]]);
      }
    }

    return paths;
  }

  // Return all possible issuers for the given certificate
  private findIssuer(certificate: x509Certificate): x509Certificate[] {
    let issuers: x509Certificate[] = [];
    let keyIdentifier: Buffer | undefined;

    // Exit early if the certificate is self-signed
    if (bufferEqual(certificate.subject, certificate.issuer)) {
      if (certificate.verify()) {
        return [certificate];
      }
    }

    // If the certificate has an authority key identifier, use that
    // to find the issuer
    if (certificate.extAuthorityKeyID) {
      keyIdentifier = certificate.extAuthorityKeyID.keyIdentifier;

      // TODO: Add support for authorityCertIssuer/authorityCertSerialNumber
      // though Fulcio doesn't appear to use these
    }

    // Find possible issuers by comparing the authorityKeyID/subjectKeyID
    // or issuer/subject. Potential issuers are added to the result array.
    this.certs.forEach((possibleIssuer) => {
      if (keyIdentifier) {
        if (possibleIssuer.extSubjectKeyID) {
          if (
            bufferEqual(
              possibleIssuer.extSubjectKeyID.keyIdentifier,
              keyIdentifier
            )
          ) {
            issuers.push(possibleIssuer);
          }
          return;
        }
      }

      // Fallback to comparing certificate issuer and subject if
      // subjectKey/authorityKey extensions are not present
      if (bufferEqual(possibleIssuer.subject, certificate.issuer)) {
        issuers.push(possibleIssuer);
      }
    });

    // Remove any issuers which fail to verify the certificate
    issuers = issuers.filter((issuer) => {
      try {
        return certificate.verify(issuer);
      } catch (ex) {
        return false;
      }
    });

    return issuers;
  }

  private checkPath(path: x509Certificate[]): void {
    // Certificate path must be at least 2 certificates long
    if (path.length < 2) {
      throw new Error('Certificate path is too short');
    }

    // Check that the leaf certificate is not a CA
    if (path[0].isCA) {
      throw new Error('Leaf certificate is a CA');
    }

    // Ensure that all certificates beyond the leaf are CAs
    const validCAs = path.slice(1).every((cert) => cert.isCA);
    if (!validCAs) {
      throw new Error('Intermediate certificate is not a CA');
    }

    // Check that the leaf certificate has the digitalSignature key usage
    if (!path[0].extKeyUsage?.digitalSignature) {
      throw new Error('Leaf certificate does not have digitalSignature');
    }

    // Check that the leaf certificate has a subjectAltName extension
    if (!path[0].extSubjectAltName) {
      throw new Error('Leaf certificate does not have a subjectAltName');
    }

    // Check that the leaf certificate has a valid subjectAltName extension
    if (
      !path[0].extSubjectAltName.rfc822Name?.length &&
      !path[0].extSubjectAltName.uri?.length
    ) {
      throw new Error('Leaf certificate does not have a valid subjectAltName');
    }

    // Check that all certificates are valid at the check date
    const validForDate = path.every((cert) =>
      cert.validForDate(this.checkDate)
    );
    if (!validForDate) {
      throw new Error(
        'Certificate is not valid or expired at the specified date'
      );
    }

    // Certificate's issuer must match the subject of the next certificate
    // in the chain
    for (let i = path.length - 2; i >= 0; i--) {
      if (!bufferEqual(path[i].issuer, path[i + 1].subject)) {
        throw new Error('Incorrect certificate name chaining');
      }
    }
  }
}

function bufferEqual(a: Buffer, b: Buffer): boolean {
  return Buffer.compare(a, b) === 0;
}

function unique(certs: x509Certificate[]): x509Certificate[] {
  for (let i = 0; i < certs.length; i++) {
    for (let j = i + 1; j < certs.length; j++) {
      if (bufferEqual(certs[i].tbsCertificate, certs[j].tbsCertificate)) {
        certs.splice(j, 1);
        j--;
      }
    }
  }
  return certs;
}
