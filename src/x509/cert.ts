import crypto from 'crypto';
import { pem } from '../util';
import { ASN1Obj } from './asn1/obj';
import {
  x509AuthorityKeyIDExtension,
  x509BasicConstraintsExtension,
  x509Extension,
  x509KeyUsageExtension,
  x509SCTExtension,
  x509SubjectAlternativeNameExtension,
  x509SubjectKeyIDExtension,
} from './ext';

const EXTENSION_OID_KEY_USAGE = '2.5.29.15';
const EXTENSION_OID_BASIC_CONSTRAINTS = '2.5.29.19';
const EXTENSION_OID_SUBJECT_ALT_NAME = '2.5.29.17';
const EXTENSION_OID_AUTHORITY_KEY_ID = '2.5.29.35';
const EXTENSION_OID_SUBJECT_KEY_ID = '2.5.29.14';
const EXTENSION_OID_SCT = '1.3.6.1.4.1.11129.2.4.2';

// List of recognized critical extensions
// https://www.rfc-editor.org/rfc/rfc5280#section-4.2
const RECOGNIZED_EXTENSIONS = [
  EXTENSION_OID_KEY_USAGE,
  EXTENSION_OID_BASIC_CONSTRAINTS,
  EXTENSION_OID_SUBJECT_ALT_NAME,
];

const ECDSA_SIGNATURE_ALGOS: Record<string, string> = {
  '1.2.840.10045.4.3.1': 'sha224',
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
};

export class x509Certificate {
  public root: ASN1Obj;

  constructor(asn1: ASN1Obj) {
    this.root = asn1;

    if (!this.checkRecognizedExtensions()) {
      throw new Error('Certificate contains unrecognized critical extensions');
    }
  }

  public static parse(cert: Buffer | string): x509Certificate {
    const der = typeof cert === 'string' ? pem.toDER(cert) : cert;
    const asn1 = ASN1Obj.parseBuffer(der);
    return new x509Certificate(asn1);
  }

  get tbsCertificate(): Buffer {
    return this.tbsCertificateObj.raw;
  }

  get version(): string {
    // version number is the first element of the version context specific tag
    const ver = this.versionObj.subs[0].toInteger();
    return `v${(ver + BigInt(1)).toString()}`;
  }

  get notBefore(): Date {
    // notBefore is the first element of the validity sequence
    return this.validityObj.subs[0].toDate();
  }

  get notAfter(): Date {
    // notAfter is the second element of the validity sequence
    return this.validityObj.subs[1].toDate();
  }

  get issuer(): Buffer {
    return this.issuerObj.value;
  }

  get subject(): Buffer {
    return this.subjectObj.value;
  }

  get publicKey(): crypto.KeyObject {
    return crypto.createPublicKey({
      key: this.subjectPublicKeyInfoObj.raw,
      format: 'der',
      type: 'spki',
    });
  }

  get signatureAlgorithm(): string {
    const oid: string = this.signatureAlgorithmObj.subs[0].toOID();
    return ECDSA_SIGNATURE_ALGOS[oid];
  }

  get signatureValue(): Buffer {
    // Signature value is a bit string, so we need to skip the first byte
    return this.signatureValueObj.value.subarray(1);
  }

  get extKeyUsage(): x509KeyUsageExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_KEY_USAGE);
    return ext ? new x509KeyUsageExtension(ext) : undefined;
  }

  get extBasicConstraints(): x509BasicConstraintsExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_BASIC_CONSTRAINTS);
    return ext ? new x509BasicConstraintsExtension(ext) : undefined;
  }

  get extSubjectAltName(): x509SubjectAlternativeNameExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SUBJECT_ALT_NAME);
    return ext ? new x509SubjectAlternativeNameExtension(ext) : undefined;
  }

  get extAuthorityKeyID(): x509AuthorityKeyIDExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_AUTHORITY_KEY_ID);
    return ext ? new x509AuthorityKeyIDExtension(ext) : undefined;
  }

  get extSubjectKeyID(): x509SubjectKeyIDExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SUBJECT_KEY_ID);
    return ext ? new x509SubjectKeyIDExtension(ext) : undefined;
  }

  get extSCT(): x509SCTExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SCT);
    return ext ? new x509SCTExtension(ext) : undefined;
  }

  get isCA(): boolean {
    const ca = this.extBasicConstraints?.isCA || false;

    // If the KeyUsage extension is present, keyCertSign must be set
    if (this.extKeyUsage) {
      ca && this.extKeyUsage.keyCertSign;
    }

    return ca;
  }

  public verify(issuerCertificate?: x509Certificate): boolean {
    // Use the issuer's public key if provided, otherwise use the subject's
    const publicKey = issuerCertificate?.publicKey || this.publicKey;

    return crypto.verify(
      this.signatureAlgorithm,
      this.tbsCertificate,
      publicKey,
      this.signatureValue
    );
  }

  public validForDate(date: Date): boolean {
    return this.notBefore <= date && date <= this.notAfter;
  }

  public equals(other: x509Certificate): boolean {
    return this.root.raw.equals(other.root.raw);
  }

  private findExtension(oid: string): ASN1Obj | undefined {
    // The extension list is the first (and only) element of the extensions
    // context specific tag
    const extSeq = this.extensionsObj?.subs[0];

    // Find the extension with the given OID. The OID will always be the first
    // element of the extension sequence
    return extSeq?.subs.find((ext) => ext.subs[0].toOID() === oid);
  }

  // A certificate should be considered invalid if it contains critical
  // extensions that are not recognized
  private checkRecognizedExtensions(): boolean {
    // The extension list is the first (and only) element of the extensions
    // context specific tag
    const extSeq = this.extensionsObj?.subs[0];

    const exts = extSeq?.subs.map((ext) => new x509Extension(ext));

    // Check for unrecognized critical extensions
    return (
      !exts ||
      exts.every(
        (ext) => !ext.critical || RECOGNIZED_EXTENSIONS.includes(ext.oid)
      )
    );
  }

  /////////////////////////////////////////////////////////////////////////////
  // The following properties use the documented x509 structure to locate the
  // desired ASN.1 object
  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.1
  private get tbsCertificateObj(): ASN1Obj {
    // tbsCertificate is the first element of the certificate sequence
    return this.root.subs[0];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2
  private get signatureAlgorithmObj(): ASN1Obj {
    // signatureAlgorithm is the second element of the certificate sequence
    return this.root.subs[1];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.3
  private get signatureValueObj(): ASN1Obj {
    // signatureValue is the third element of the certificate sequence
    return this.root.subs[2];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.1
  private get versionObj(): ASN1Obj {
    // version is the first element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[0];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4
  private get issuerObj(): ASN1Obj {
    // issuer is the fourth element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[3];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
  private get validityObj(): ASN1Obj {
    // version is the fifth element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[4];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.6
  private get subjectObj(): ASN1Obj {
    // subject is the sixth element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[5];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7
  private get subjectPublicKeyInfoObj(): ASN1Obj {
    // subjectPublicKeyInfo is the seventh element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[6];
  }

  // Extensions can't be located by index because their position varies. Instead,
  // we need to find the extensions context specific tag
  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.9
  private get extensionsObj(): ASN1Obj | undefined {
    return this.tbsCertificateObj.subs.find((sub) =>
      sub.tag.isContextSpecific(0x03)
    );
  }
}
