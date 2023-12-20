import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import * as pvutils from 'pvutils';

const CERT_HASH = 'certHash';
const ISSUER_SERIAL = 'issuerSerial';

interface IESSCertIDv2 {
  certHash: asn1js.OctetString;
  issuerSerial: pkijs.IssuerSerial;
}

type ESSCertIDv2Parameters = pkijs.PkiObjectParameters & Partial<IESSCertIDv2>;

// https://datatracker.ietf.org/doc/html/rfc5035#section-4
export class ESSCertIDv2 extends pkijs.PkiObject implements IESSCertIDv2 {
  public static override CLASS_NAME = 'ESSCertIDv2';

  public certHash!: asn1js.OctetString;
  public issuerSerial!: pkijs.IssuerSerial;

  constructor(parameters: ESSCertIDv2Parameters = {}) {
    super();

    this.certHash = pvutils.getParametersValue(
      parameters,
      CERT_HASH,
      new asn1js.OctetString()
    );
    this.issuerSerial = pvutils.getParametersValue(
      parameters,
      ISSUER_SERIAL,
      new pkijs.IssuerSerial()
    );
  }

  public override toSchema(): asn1js.Sequence {
    const result = new asn1js.Sequence({
      value: [this.certHash, this.issuerSerial.toSchema()],
    });

    return result;
  }

  /* istanbul ignore next */
  public override fromSchema(): void {
    throw new Error('Not implemented');
  }

  /* istanbul ignore next */
  public override toJSON(): IESSCertIDv2 {
    throw new Error('Not implemented');
  }
}
