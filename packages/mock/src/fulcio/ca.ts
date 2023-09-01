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
import * as asn1js from 'asn1js';
import type { KeyPairKeyObjectResult } from 'crypto';
import {
  DIGEST_SHA256,
  KEY_ALGORITHM_ECDSA_P256,
  SIGNING_ALGORITHM_ECDSA_SHA384,
} from '../constants';
import { keyObjectToCryptoKey } from '../util/key';
import { createRootCertificate } from '../util/root-cert';
import type { CTLog } from './ctlog';

const ISSUER = 'CN=sigstore,O=sigstore.mock';

const OID_SIGNED_CERTIFICATE_TIMESTAMP_LIST = '1.3.6.1.4.1.11129.2.4.2';

const MS_PER_MINUTE = 1000 * 60;

export interface CA {
  rootCertificate: Buffer;
  issueCertificate: (options: CertificateRequestOptions) => Promise<Buffer>;
}

export interface CertificateRequestOptions {
  publicKey: Buffer;
  subjectAltName: string;
  extensions?: ExtensionValue[];
}

interface ExtensionValue {
  oid: string;
  value: string;
}

// Initialize the mock CA. Starts by generating a root key pair and self-signed
// certificate. The root certificate is used to sign any certificates issued by
// the #issueCertificate method. Doing this work in a function allows us to
// work around the fact that some of these operations are async and can't be
// done in the constructor.
export async function initializeCA(
  keyPair: KeyPairKeyObjectResult,
  ctLog?: CTLog
): Promise<CA> {
  const cryptoKeyPair = {
    privateKey: await keyObjectToCryptoKey(keyPair.privateKey),
    publicKey: await keyObjectToCryptoKey(keyPair.publicKey),
  };

  const root = await createRootCertificate(
    ISSUER,
    cryptoKeyPair,
    SIGNING_ALGORITHM_ECDSA_SHA384
  );

  return new CAImpl({
    keyPair: root.keyPair,
    rootCertificate: root.cert,
    ctLog,
  });
}

class CAImpl implements CA {
  private root: x509.X509Certificate;
  private keyPair: CryptoKeyPair;
  private ctLog?: CTLog;
  private crypto: Crypto;

  constructor(options: {
    rootCertificate: x509.X509Certificate;
    keyPair: CryptoKeyPair;
    ctLog?: CTLog;
  }) {
    this.root = options.rootCertificate;
    this.ctLog = options.ctLog;
    this.keyPair = options.keyPair;
    this.crypto = new Crypto();
  }

  public get rootCertificate(): Buffer {
    return Buffer.from(this.root.rawData);
  }

  public async issueCertificate(
    opts: CertificateRequestOptions
  ): Promise<Buffer> {
    // convert key to CryptoKey
    const key = await this.crypto.subtle.importKey(
      'spki',
      opts.publicKey,
      KEY_ALGORITHM_ECDSA_P256,
      true,
      ['sign', 'verify']
    );

    // https://github.com/sigstore/fulcio/blob/549813ca04ae02b4a19181817a90a66c2a00960c/pkg/ca/common.go#L29
    const tbs = {
      serialNumber: '11182004',
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 10 * MS_PER_MINUTE),
      issuer: ISSUER,
      publicKey: key,
      signingAlgorithm: SIGNING_ALGORITHM_ECDSA_SHA384,
      signingKey: this.keyPair.privateKey,
      extensions: [
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.codeSigning]),
        new x509.SubjectAlternativeNameExtension(
          [{ type: 'url', value: opts.subjectAltName }],
          true
        ),
        await x509.SubjectKeyIdentifierExtension.create(
          key,
          false,
          this.crypto
        ),
        await x509.AuthorityKeyIdentifierExtension.create(
          this.keyPair.publicKey,
          false,
          this.crypto
        ),
        ...generateExtensions(opts.extensions || []),
      ],
    } satisfies x509.X509CertificateCreateParams;

    if (this.ctLog) {
      // Pre-sign certificate for submission to CT Log
      const preCert = await x509.X509CertificateGenerator.create(
        tbs,
        this.crypto
      );

      // Submit to CT Log in exchange for SCT
      const issuerID = await this.issuerID;
      const sct = await this.ctLog.log(preCert.rawData, issuerID);

      // Add the SCT extension to the certificate
      tbs.extensions.push(extSCTList(sct));
    }

    const cert = await x509.X509CertificateGenerator.create(tbs, this.crypto);
    return Buffer.from(cert.rawData);
  }

  private get issuerID(): Promise<ArrayBuffer> {
    return this.crypto.subtle
      .exportKey('spki', this.keyPair.publicKey)
      .then((key) => this.crypto.subtle.digest({ name: DIGEST_SHA256 }, key));
  }
}

const extSCTList = (sct: ArrayBuffer): x509.Extension => {
  // Manually construct the SCTList
  const sctBuffer = sct;
  const sctList = Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from([sctBuffer.byteLength]),
    Buffer.from(sctBuffer),
  ]);

  // Wrap the SCTList in an OctetString
  const sctListWrapper = new asn1js.OctetString({ valueHex: sctList });

  return new x509.Extension(
    OID_SIGNED_CERTIFICATE_TIMESTAMP_LIST,
    false,
    sctListWrapper.toBER(false)
  );
};

const generateExtensions = (extensions: ExtensionValue[]): x509.Extension[] =>
  extensions.map((extension) => {
    const value = new asn1js.Utf8String({ value: extension.value });
    return new x509.Extension(extension.oid, false, value.toBER(false));
  });
