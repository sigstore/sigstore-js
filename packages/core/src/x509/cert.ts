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
import { ASN1Obj } from '../asn1';
import * as crypto from '../crypto';
import { ECDSA_SIGNATURE_ALGOS } from '../oid';
import * as pem from '../pem';
import {
  X509AuthorityKeyIDExtension,
  X509BasicConstraintsExtension,
  X509Extension,
  X509KeyUsageExtension,
  X509SCTExtension,
  X509SubjectAlternativeNameExtension,
  X509SubjectKeyIDExtension,
} from './ext';

const EXTENSION_OID_SUBJECT_KEY_ID = '2.5.29.14';
const EXTENSION_OID_KEY_USAGE = '2.5.29.15';
const EXTENSION_OID_SUBJECT_ALT_NAME = '2.5.29.17';
const EXTENSION_OID_BASIC_CONSTRAINTS = '2.5.29.19';
const EXTENSION_OID_AUTHORITY_KEY_ID = '2.5.29.35';
export const EXTENSION_OID_SCT = '1.3.6.1.4.1.11129.2.4.2';

export class X509Certificate {
  public root: ASN1Obj;

  constructor(asn1: ASN1Obj) {
    this.root = asn1;
  }

  public static parse(cert: Buffer | string): X509Certificate {
    const der = typeof cert === 'string' ? pem.toDER(cert) : cert;
    const asn1 = ASN1Obj.parseBuffer(der);
    return new X509Certificate(asn1);
  }

  get tbsCertificate(): ASN1Obj {
    return this.tbsCertificateObj;
  }

  get version(): string {
    // version number is the first element of the version context specific tag
    const ver = this.versionObj.subs[0].toInteger();
    return `v${(ver + BigInt(1)).toString()}`;
  }

  get serialNumber(): Buffer {
    return this.serialNumberObj.value;
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

  get publicKey(): Buffer {
    return this.subjectPublicKeyInfoObj.toDER();
  }

  get signatureAlgorithm(): string {
    const oid: string = this.signatureAlgorithmObj.subs[0].toOID();
    return ECDSA_SIGNATURE_ALGOS[oid];
  }

  get signatureValue(): Buffer {
    // Signature value is a bit string, so we need to skip the first byte
    return this.signatureValueObj.value.subarray(1);
  }

  get subjectAltName(): string | undefined {
    const ext = this.extSubjectAltName;
    return ext?.uri || /* istanbul ignore next */ ext?.rfc822Name;
  }

  get extensions(): ASN1Obj[] {
    // The extension list is the first (and only) element of the extensions
    // context specific tag
    /* istanbul ignore next */
    const extSeq = this.extensionsObj?.subs[0];
    /* istanbul ignore next */
    return extSeq?.subs || [];
  }

  get extKeyUsage(): X509KeyUsageExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_KEY_USAGE);
    return ext ? new X509KeyUsageExtension(ext) : undefined;
  }

  get extBasicConstraints(): X509BasicConstraintsExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_BASIC_CONSTRAINTS);
    return ext ? new X509BasicConstraintsExtension(ext) : undefined;
  }

  get extSubjectAltName(): X509SubjectAlternativeNameExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SUBJECT_ALT_NAME);
    return ext ? new X509SubjectAlternativeNameExtension(ext) : undefined;
  }

  get extAuthorityKeyID(): X509AuthorityKeyIDExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_AUTHORITY_KEY_ID);
    return ext ? new X509AuthorityKeyIDExtension(ext) : undefined;
  }

  get extSubjectKeyID(): X509SubjectKeyIDExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SUBJECT_KEY_ID);
    return ext
      ? new X509SubjectKeyIDExtension(ext)
      : /* istanbul ignore next */ undefined;
  }

  get extSCT(): X509SCTExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SCT);
    return ext ? new X509SCTExtension(ext) : undefined;
  }

  get isCA(): boolean {
    const ca = this.extBasicConstraints?.isCA || false;

    // If the KeyUsage extension is present, keyCertSign must be set
    /* istanbul ignore else */
    if (this.extKeyUsage) {
      return ca && this.extKeyUsage.keyCertSign;
    }

    // TODO: test coverage for this case
    /* istanbul ignore next */
    return ca;
  }

  public extension(oid: string): X509Extension | undefined {
    const ext = this.findExtension(oid);
    return ext ? new X509Extension(ext) : undefined;
  }

  public verify(issuerCertificate?: X509Certificate): boolean {
    // Use the issuer's public key if provided, otherwise use the subject's
    const publicKey = issuerCertificate?.publicKey || this.publicKey;
    const key = crypto.createPublicKey(publicKey);

    return crypto.verify(
      this.tbsCertificate.toDER(),
      key,
      this.signatureValue,
      this.signatureAlgorithm
    );
  }

  public validForDate(date: Date): boolean {
    return this.notBefore <= date && date <= this.notAfter;
  }

  public equals(other: X509Certificate): boolean {
    return this.root.toDER().equals(other.root.toDER());
  }

  // Creates a copy of the certificate with a new buffer
  public clone(): X509Certificate {
    const der = this.root.toDER();
    const clone = Buffer.alloc(der.length);
    der.copy(clone);
    return X509Certificate.parse(clone);
  }

  private findExtension(oid: string): ASN1Obj | undefined {
    // Find the extension with the given OID. The OID will always be the first
    // element of the extension sequence
    return this.extensions.find((ext) => ext.subs[0].toOID() === oid);
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

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
  private get serialNumberObj(): ASN1Obj {
    // serialNumber is the second element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[1];
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
