import { ASN1Obj } from './asn1/obj';
import { SignedCertificateTimestamp } from './sct';

// https://www.rfc-editor.org/rfc/rfc5280#section-4.1
class x509Extension {
  protected root: ASN1Obj;

  constructor(asn1: ASN1Obj) {
    this.root = asn1;
  }

  get oid(): string {
    return this.root.subs[0].toOID();
  }

  get critical(): boolean {
    // The critical field is optional and will be the second element of the
    // extension sequence if present. Default to false if not present.
    return this.root.subs.length === 3 ? this.root.subs[1].toBoolean() : false;
  }

  protected get extnValueObj(): ASN1Obj {
    // The extnValue field will be the last element of the extension sequence
    return this.root.subs[this.root.subs.length - 1];
  }
}

// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
export class x509BasicConstraintsExtension extends x509Extension {
  constructor(asn1: ASN1Obj) {
    super(asn1);
  }

  get isCA(): boolean {
    return this.sequence.subs[0].toBoolean();
  }

  get pathLenConstraint(): bigint | undefined {
    return this.sequence.subs.length > 1
      ? this.sequence.subs[1].toInteger()
      : undefined;
  }

  // The extnValue field contains a single sequence wrapping the isCA and
  // pathLenConstraint.
  private get sequence(): ASN1Obj {
    return this.extnValueObj.subs[0];
  }
}

// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
export class x509KeyUsageExtension extends x509Extension {
  constructor(asn1: ASN1Obj) {
    super(asn1);
  }

  get digitalSignature(): boolean {
    return this.bitString[0] === 1;
  }

  get keyCertSign(): boolean {
    return this.bitString[5] === 1;
  }

  get crlSign(): boolean {
    return this.bitString[6] === 1;
  }

  // The extnValue field contains a single bit string which is a bit mask
  // indicating which key usages are enabled.
  private get bitString(): number[] {
    return this.extnValueObj.subs[0].toBitString();
  }
}

// https://www.rfc-editor.org/rfc/rfc6962#section-3.3
export class x509SCTExtension extends x509Extension {
  constructor(asn1: ASN1Obj) {
    super(asn1);
  }

  get signedCertificateTimestamps(): SignedCertificateTimestamp[] {
    const buf = this.extnValueObj.subs[0].value;
    let pos = 0;

    // The overall list length is encoded in the first two bytes
    const end = buf.readUInt16BE(pos) + 2;
    pos += 2;

    const sctList = [];
    while (pos < end) {
      // Read the length of the next SCT
      const sctLength = buf.readUInt16BE(pos);
      pos += 2;

      // Slice out the bytes for the next SCT and parse it
      const sct = buf.subarray(pos, pos + sctLength);
      sctList.push(SignedCertificateTimestamp.parseBuffer(sct));
      pos += sctLength;
    }

    if (pos !== end) {
      throw new Error('SCT list length does not match actual length');
    }

    return sctList;
  }
}
