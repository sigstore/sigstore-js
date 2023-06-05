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
import { ASN1Obj } from '../util/asn1';
import { ByteStream } from '../util/stream';
import { SignedCertificateTimestamp } from './sct';

// https://www.rfc-editor.org/rfc/rfc5280#section-4.1
export class x509Extension {
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

  get value(): Buffer {
    return this.extnValueObj.value;
  }

  get valueObj(): ASN1Obj {
    return this.extnValueObj;
  }

  protected get extnValueObj(): ASN1Obj {
    // The extnValue field will be the last element of the extension sequence
    return this.root.subs[this.root.subs.length - 1];
  }
}

// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
export class x509BasicConstraintsExtension extends x509Extension {
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

// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
export class x509SubjectAlternativeNameExtension extends x509Extension {
  get rfc822Name(): string | undefined {
    return this.findGeneralName(0x01)?.value.toString('ascii');
  }

  get uri(): string | undefined {
    return this.findGeneralName(0x06)?.value.toString('ascii');
  }

  // Retrieve the value of an otherName with the given OID.
  public otherName(oid: string): string | undefined {
    const otherName = this.findGeneralName(0x00);

    if (otherName === undefined) {
      return undefined;
    }

    // The otherName is a sequence containing an OID and a value.
    // Need to check that the OID matches the one we're looking for.
    const otherNameOID = otherName.subs[0].toOID();
    if (otherNameOID !== oid) {
      return undefined;
    }

    // The otherNameValue is a sequence containing the actual value.
    const otherNameValue = otherName.subs[1];
    return otherNameValue.subs[0].value.toString('ascii');
  }

  private findGeneralName(tag: number): ASN1Obj | undefined {
    return this.generalNames.find((gn) => gn.tag.isContextSpecific(tag));
  }

  // The extnValue field contains a sequence of GeneralNames.
  private get generalNames(): ASN1Obj[] {
    return this.extnValueObj.subs[0].subs;
  }
}

// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
export class x509AuthorityKeyIDExtension extends x509Extension {
  get keyIdentifier(): Buffer | undefined {
    return this.findSequenceMember(0x00)?.value;
  }

  private findSequenceMember(tag: number): ASN1Obj | undefined {
    return this.sequence.subs.find((el) => el.tag.isContextSpecific(tag));
  }

  // The extnValue field contains a single sequence wrapping the keyIdentifier
  private get sequence(): ASN1Obj {
    return this.extnValueObj.subs[0];
  }
}

// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
export class x509SubjectKeyIDExtension extends x509Extension {
  get keyIdentifier(): Buffer {
    return this.extnValueObj.subs[0].value;
  }
}

// https://www.rfc-editor.org/rfc/rfc6962#section-3.3
export class x509SCTExtension extends x509Extension {
  constructor(asn1: ASN1Obj) {
    super(asn1);
  }

  get signedCertificateTimestamps(): SignedCertificateTimestamp[] {
    const buf = this.extnValueObj.subs[0].value;
    const stream = new ByteStream(buf);

    // The overall list length is encoded in the first two bytes -- note this
    // is the length of the list in bytes, NOT the number of SCTs in the list
    const end = stream.getUint16() + 2;

    const sctList = [];
    while (stream.position < end) {
      // Read the length of the next SCT
      const sctLength = stream.getUint16();

      // Slice out the bytes for the next SCT and parse it
      const sct = stream.getBlock(sctLength);
      sctList.push(SignedCertificateTimestamp.parse(sct));
    }

    if (stream.position !== end) {
      throw new Error('SCT list length does not match actual length');
    }

    return sctList;
  }
}
