/*
Copyright 2022 The Sigstore Authors.

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
import { VerificationError } from '../../error';
import * as sigstore from '../../types/sigstore';
import { x509Certificate } from '../../x509/cert';
import { verifyCertificateChain } from '../../x509/verify';

export function verifyChain(
  certificate: sigstore.X509Certificate,
  certificateAuthorities: sigstore.CertificateAuthority[]
): x509Certificate[] {
  const untrustedCert = x509Certificate.parse(certificate.rawBytes);

  // Filter the list of certificate authorities to those which are valid for the
  // signing certificate's notBefore date.
  const validCAs = filterCertificateAuthorities(
    certificateAuthorities,
    untrustedCert.notBefore
  );

  if (validCAs.length === 0) {
    throw new VerificationError('No valid certificate authorities');
  }

  let trustedChain: x509Certificate[] = [];

  // Loop through all valid CAs and attempt to verify the certificate chain
  const verified = validCAs.find((ca) => {
    const trustedCerts = parseCerts(ca.certChain?.certificates || []);
    try {
      trustedChain = verifyCertificateChain({
        untrustedCert,
        trustedCerts,
        validAt: untrustedCert.notBefore,
      });
      return true;
    } catch (e) {
      return false;
    }
  });

  if (!verified) {
    throw new VerificationError('No valid certificate chain');
  }

  return trustedChain;
}

// Filter the list of certificate authorities to those which are valid for the
// given date.
function filterCertificateAuthorities(
  certificateAuthorities: sigstore.CertificateAuthority[],
  validAt: Date
): sigstore.CertificateAuthority[] {
  return certificateAuthorities.filter(
    (ca) =>
      ca.validFor &&
      ca.validFor.start &&
      ca.validFor.start <= validAt &&
      (!ca.validFor.end || validAt <= ca.validFor.end)
  );
}

// Parse the raw bytes of a certificate into an x509Certificate object.
function parseCerts(certs: sigstore.X509Certificate[]): x509Certificate[] {
  return certs.map((cert) => x509Certificate.parse(cert.rawBytes));
}
