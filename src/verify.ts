/*
Copyright 2022 The Sigstore Authors.

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
import { Rekor } from './client';
import { Bundle } from './types/bundle';
import { crypto, dsse, pem } from './util';

export interface VerifyOptions {
  rekor: Rekor;
}

export class Verifier {
  private rekor: Rekor;

  constructor(options: VerifyOptions) {
    this.rekor = options.rekor;
  }

  public async verify(bundle: Bundle, data?: Buffer): Promise<boolean> {
    let signature: Buffer;
    switch (bundle.content?.$case) {
      case 'dsseEnvelope': {
        const payloadType = bundle.content.dsseEnvelope.payloadType;
        const payload = bundle.content.dsseEnvelope.payload;
        data = dsse.preAuthEncoding(payloadType, payload);

        if (bundle.content.dsseEnvelope.signatures.length !== 1) {
          throw new Error('No signatures found in bundle');
        }

        signature = bundle.content.dsseEnvelope.signatures[0].sig;
        break;
      }
      case 'messageSignature':
        signature = bundle.content.messageSignature.signature;
        break;
      default:
        throw new Error('Bundle is invalid');
    }

    if (
      bundle.verificationMaterial?.content?.$case !== 'x509CertificateChain'
    ) {
      throw new Error('No certificate found in bundle');
    }

    const certificate =
      bundle.verificationMaterial.content.x509CertificateChain.certificates[0];
    const cert = pem.fromDER(certificate.derBytes);

    if (!data) {
      throw new Error('No data to verify');
    }

    return crypto.verifyBlob(data, cert, signature);
  }
}
