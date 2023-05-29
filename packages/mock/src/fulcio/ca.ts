import { Crypto, CryptoKey } from '@peculiar/webcrypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import type { CTLog } from './ctlog';

const COMMON_NAME = 'sigstore';
const ORGANIZATION_NAME = 'sigstore.mock';

const DIGEST_SHA256 = 'SHA-256';
const DIGEST_SHA384 = 'SHA-384';

const ALGORITHM_ECDSA_P384 = { name: 'ECDSA', namedCurve: 'P-384' };

const KEY_USAGE_CRL_SIGN = 0x02;
const KEY_USAGE_KEY_CERT_SIGN = 0x04;
const KEY_USAGE_DIGITAL_SIGNATURE = 0x80;

const OID_KEY_USAGE_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';
const OID_SIGNED_CERTIFICATE_TIMESTAMP_LIST = '1.3.6.1.4.1.11129.2.4.2';

interface CryptoKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

interface ExtensionValue {
  oid: string;
  value: string;
}

export interface CertificateRequestOptions {
  publicKey: Buffer;
  subjectAltName: string;
  extensions?: ExtensionValue[];
}
export interface CA {
  rootCertificate: Buffer;
  issueCertificate: (options: CertificateRequestOptions) => Promise<Buffer>;
}

export async function initializeCA(ctLog?: CTLog): Promise<CA> {
  const crypto = new pkijs.CryptoEngine({ crypto: new Crypto() });

  const keyPair = await crypto.generateKey(ALGORITHM_ECDSA_P384, true, [
    'sign',
    'verify',
  ]);

  const rootCertificate = await generateRootCertificate(keyPair, crypto)
    .then((cert) => cert.toSchema(true).toBER(false))
    .then((bytes) => Buffer.from(bytes));

  return new CAImpl({ keyPair, ctLog, rootCertificate, crypto });
}

class CAImpl implements CA {
  public readonly rootCertificate: Buffer;
  private keyPair: CryptoKeyPair;
  private ctLog?: CTLog;
  private crypto: pkijs.CryptoEngine;

  constructor(options: {
    rootCertificate: Buffer;
    keyPair: CryptoKeyPair;
    ctLog?: CTLog;
    crypto: pkijs.CryptoEngine;
  }) {
    this.rootCertificate = options.rootCertificate;
    this.ctLog = options.ctLog;
    this.keyPair = options.keyPair;
    this.crypto = options.crypto;
  }

  public async issueCertificate(
    opts: CertificateRequestOptions
  ): Promise<Buffer> {
    const cert = new pkijs.Certificate();
    cert.extensions = [];
    cert.version = 2;
    cert.serialNumber = new asn1js.Integer({ value: 11182004 });

    // Convert key to CryptoKey
    const key = await this.crypto.importKey(
      'spki',
      opts.publicKey,
      { name: 'ECDSA', namedCurve: 'P-256' } as any,
      true,
      ['sign', 'verify']
    );
    const keyID = await this.crypto.digest('SHA-1', opts.publicKey);

    // Issuer
    const dname = distinguishedName(COMMON_NAME, ORGANIZATION_NAME);
    cert.issuer.typesAndValues.push(...dname);

    // Validity
    const { notBefore, notAfter } = validity(10);
    cert.notBefore.value = notBefore;
    cert.notAfter.value = notAfter;

    // Subject Public Key Info
    await cert.subjectPublicKeyInfo.importKey(key, this.crypto);

    // Subject Key Identifier
    cert.extensions.push(extSubjectKeyIdentifier(keyID));

    // Authority Key Identifier
    const issuerID = await this.crypto.digest(
      'SHA-1',
      await this.crypto.exportKey('raw', this.keyPair.publicKey)
    );
    cert.extensions.push(extAuthorityKeyIdentifier(issuerID));

    // Subject Alt Name
    cert.extensions.push(extSubjectAltName(opts.subjectAltName));

    // Key Usage Extension
    cert.extensions.push(extKeyUsage(KEY_USAGE_DIGITAL_SIGNATURE));

    // Extended Key Usage Extension
    cert.extensions.push(extExtendedKeyUsage([OID_KEY_USAGE_CODE_SIGNING]));

    // OIDC Token Claim Extensions
    cert.extensions.push(...generateExtensions(opts.extensions || []));

    if (this.ctLog) {
      // Pre-sign certificate for submission to CT Log
      await cert.sign(this.keyPair.privateKey, DIGEST_SHA384, this.crypto);

      // Submit to CT Log in exchange for SCT
      const issuerID = await this.issuerID;
      const sct = await this.ctLog.log(cert, issuerID);

      // Signed Certificate Timestamp Extension
      cert.extensions.push(extSignedCertificateTimestampList(sct));
    }

    // Re-sign certificate with SCT
    await cert.sign(this.keyPair.privateKey, DIGEST_SHA384, this.crypto);

    return Buffer.from(cert.toSchema(true).toBER(false));
  }

  private get issuerID(): Promise<ArrayBuffer> {
    return this.crypto
      .exportKey('spki', this.keyPair.publicKey)
      .then((key) => this.crypto.digest({ name: DIGEST_SHA256 }, key));
  }
}

const generateRootCertificate = async (
  keyPair: CryptoKeyPair,
  crypto: pkijs.ICryptoEngine
): Promise<pkijs.Certificate> => {
  const cert = new pkijs.Certificate();

  // Calculate Subject Key Identifier
  const keyID = await crypto.digest(
    'SHA-1',
    await crypto.exportKey('raw', keyPair.publicKey)
  );

  cert.extensions = [];
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });

  // Subject / Issuer
  const dname = distinguishedName(COMMON_NAME, ORGANIZATION_NAME);
  cert.subject.typesAndValues.push(...dname);
  cert.issuer.typesAndValues.push(...dname);

  // Validity
  const { notBefore, notAfter } = validity(10);
  cert.notBefore.value = notBefore;
  cert.notAfter.value = notAfter;

  // Subject Public Key Info
  await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey, crypto);
  cert.extensions.push(extSubjectKeyIdentifier(keyID));
  cert.extensions.push(extAuthorityKeyIdentifier(keyID));

  // Basic Constraints Extension
  cert.extensions.push(extBasicConstraints());

  // Key Usage Extension
  cert.extensions.push(
    extKeyUsage(KEY_USAGE_CRL_SIGN | KEY_USAGE_KEY_CERT_SIGN)
  );

  // Extended Key Usage Extension
  cert.extensions.push(extExtendedKeyUsage([OID_KEY_USAGE_CODE_SIGNING]));

  // Sign certificate
  await cert.sign(keyPair.privateKey, DIGEST_SHA384, crypto);

  return cert;
};

const validity = (minutes: number): { notBefore: Date; notAfter: Date } => {
  const notBefore = new Date();
  const notAfter = new Date(notBefore.valueOf() + 1000 * 60 * minutes);

  return { notBefore, notAfter };
};

const distinguishedName = (
  commonName: string,
  orgName: string
): pkijs.AttributeTypeAndValue[] => {
  const attrs = [];
  attrs.push(
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3', // Common name
      value: new asn1js.PrintableString({ value: commonName }),
    })
  );
  attrs.push(
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.10', // organization name
      value: new asn1js.PrintableString({ value: orgName }),
    })
  );

  return attrs;
};

const extSubjectAltName = (name: string): pkijs.Extension => {
  const altName = new pkijs.GeneralNames({
    names: [new pkijs.GeneralName({ type: 6, value: name })],
  });

  return new pkijs.Extension({
    extnID: pkijs.id_SubjectAltName,
    critical: true,
    extnValue: altName.toSchema().toBER(false),
  });
};

const extSubjectKeyIdentifier = (key: ArrayBuffer): pkijs.Extension => {
  const keyID = new asn1js.OctetString({ valueHex: key });

  return new pkijs.Extension({
    extnID: pkijs.id_SubjectKeyIdentifier,
    critical: false,
    extnValue: keyID.toBER(false),
  });
};

const extAuthorityKeyIdentifier = (key: ArrayBuffer): pkijs.Extension => {
  const keyID = new asn1js.OctetString({ valueHex: key });
  const authority = new pkijs.AuthorityKeyIdentifier({ keyIdentifier: keyID });

  return new pkijs.Extension({
    extnID: pkijs.id_AuthorityKeyIdentifier,
    critical: false,
    extnValue: authority.toSchema().toBER(false),
  });
};

const extBasicConstraints = (ca = true): pkijs.Extension => {
  const basicConstr = new pkijs.BasicConstraints({ cA: ca });

  return new pkijs.Extension({
    extnID: pkijs.id_BasicConstraints,
    critical: true,
    extnValue: basicConstr.toSchema().toBER(false),
  });
};

const extKeyUsage = (map: number): pkijs.Extension => {
  const bitArray = new ArrayBuffer(1);
  const bitView = new Uint8Array(bitArray);
  bitView[0] = map;
  const keyUsage = new asn1js.BitString({ valueHex: bitArray });

  return new pkijs.Extension({
    extnID: pkijs.id_KeyUsage,
    critical: true,
    extnValue: keyUsage.toBER(false),
  });
};

const extExtendedKeyUsage = (purposes: string[]): pkijs.Extension => {
  const extKeyUsage = new pkijs.ExtKeyUsage({
    keyPurposes: purposes,
  });

  return new pkijs.Extension({
    extnID: pkijs.id_ExtKeyUsage,
    critical: false,
    extnValue: extKeyUsage.toSchema().toBER(false),
  });
};

const extSignedCertificateTimestampList = (
  sct: pkijs.SignedCertificateTimestamp
): pkijs.Extension => {
  // Manually construct the SCTList (couldn't get pkijs to do this properly)
  const sctBuffer = sct.toStream().buffer;
  const sctList = Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from([sctBuffer.byteLength]),
    Buffer.from(sctBuffer),
  ]);

  // Wrap the SCTList in an OctetString
  const sctListWrapper = new asn1js.OctetString({ valueHex: sctList });

  return new pkijs.Extension({
    extnID: OID_SIGNED_CERTIFICATE_TIMESTAMP_LIST,
    critical: false,
    extnValue: sctListWrapper.toBER(false),
  });
};

const generateExtensions = (
  extensions: ExtensionValue[]
): pkijs.Extension[] => {
  return extensions.map((extension) => {
    const str = new asn1js.Utf8String({ value: extension.value });

    return new pkijs.Extension({
      extnID: extension.oid,
      critical: false,
      extnValue: str.toBER(false),
    });
  });
};
