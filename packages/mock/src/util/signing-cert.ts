import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import * as pvutils from 'pvutils';
import { ESSCertIDv2 } from './ess-cert-id';

const CERTS = 'certs';

interface ISigningCertificateV2 {
  certs: ESSCertIDv2[];
}

type SigningCertificateV2Parameters = pkijs.PkiObjectParameters &
  Partial<ISigningCertificateV2>;

// https://datatracker.ietf.org/doc/html/rfc5035#section-3
export class SigningCertificateV2
  extends pkijs.PkiObject
  implements ISigningCertificateV2
{
  public static override CLASS_NAME = 'SigningCertificateV2';

  public certs!: ESSCertIDv2[];

  constructor(parameters: SigningCertificateV2Parameters = {}) {
    super();

    this.certs = pvutils.getParametersValue(parameters, CERTS, []);
  }

  public override toSchema(): asn1js.Sequence {
    return new asn1js.Sequence({
      value: Array.from(this.certs, (o) => o.toSchema()),
    });
  }

  /* istanbul ignore next */
  public override fromSchema(): void {
    throw new Error('Not implemented');
  }

  /* istanbul ignore next */
  public override toJSON(): ISigningCertificateV2 {
    throw new Error('Not implemented');
  }
}
