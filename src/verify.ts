import { Rekor } from './rekor';
import { hash, verifyBlob } from './crypto';
import { base64Decode } from './util';
import { KeyLike } from 'crypto';

export interface VerifyOptions {
  rekor: Rekor;
}

export class Verifier {
  private rekor: Rekor;

  constructor(options: VerifyOptions) {
    this.rekor = options.rekor;
  }

  public async verify(
    payload: Buffer,
    signature: string,
    certificate?: KeyLike
  ): Promise<boolean> {
    signature = signature.trim();

    if (!certificate) {
      certificate = await this.lookupCertificate(payload, signature);
    }

    if (certificate) {
      return verifyBlob(certificate, payload, signature);
    } else {
      return false;
    }
  }

  // Find certificate in Rekor log
  private async lookupCertificate(
    payload: Buffer,
    signature: string
  ): Promise<KeyLike | undefined> {
    // Calculate artifact digest
    const digest = hash(payload);

    // Look-up Rekor entries by artifact digest
    const uuids = await this.rekor.searchLog({ hash: `sha256:${digest}` });

    let b64Cert;
    // Find Rekor entry with matching artifact signature
    // TODO: purposefully doing this lookup serially for now -- consider parallelizing
    for (const uuid of uuids) {
      const entry = await this.rekor.getEntry(uuid);
      const body = JSON.parse(base64Decode(entry.body));

      if (body.spec.signature.content == signature) {
        b64Cert = body.spec.signature.publicKey.content;
        break;
      }
    }

    // If we have a cert here it means we found a matching entry
    if (b64Cert) {
      return base64Decode(b64Cert);
    }
  }
}
