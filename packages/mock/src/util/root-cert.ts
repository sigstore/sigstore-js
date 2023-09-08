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
import { Crypto } from '@peculiar/webcrypto';
import x509 from '@peculiar/x509';

const MS_PER_DAY = 1000 * 60 * 60 * 24;

interface CertWithKey {
  cert: x509.X509Certificate;
  keyPair: CryptoKeyPair;
}

export async function createRootCertificate(
  name: string,
  keyPair: CryptoKeyPair,
  signAlgo: EcdsaParams
): Promise<CertWithKey> {
  const crypto = new Crypto();

  const tbs: x509.X509CertificateCreateSelfSignedParams = {
    serialNumber: '01',
    name: name,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * MS_PER_DAY),
    signingAlgorithm: signAlgo,
    keys: keyPair,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.keyCertSign,
        true
      ),
      await x509.SubjectKeyIdentifierExtension.create(
        keyPair.publicKey,
        false,
        crypto
      ),
      await x509.AuthorityKeyIdentifierExtension.create(
        keyPair.publicKey,
        false,
        crypto
      ),
    ],
  };

  return {
    cert: await x509.X509CertificateGenerator.createSelfSigned(tbs, crypto),
    keyPair,
  };
}
