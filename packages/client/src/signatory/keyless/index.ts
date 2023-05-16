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
import { InternalError } from '../../error';
import { crypto, oidc } from '../../util';
import { CA, CAClient } from './ca';

import type { Provider } from '../../identity';
import type { FetchOptions } from '../../types/fetch';
import type { Endorsement, Signatory } from '../signatory';

export type KeylessSignerOptions = {
  fulcioBaseURL: string;
  identityProviders: Provider[];
} & FetchOptions;

// Signatory implementation which uses an ephemeral keypair to sign artifacts.
// The private key is never persisted, and the public key is sent to Fulcio
// along with an OIDC token to create a signing certificate.
export class KeylessSigner implements Signatory {
  private ca: CA;
  private identityProviders: Provider[];

  constructor(options: KeylessSignerOptions) {
    this.ca = new CAClient(options);
    this.identityProviders = options.identityProviders;
  }

  public async sign(data: Buffer): Promise<Endorsement> {
    // Create emphemeral key pair
    const keypair = crypto.generateKeyPair();

    // Retrieve identity token from one of the supplied identity providers
    const identityToken = await this.getIdentityToken();

    // Extract challenge claim from OIDC token
    const subject = oidc.extractJWTSubject(identityToken);

    // Construct challenge value by encrypting subject with private key
    const challenge = crypto.signBlob(Buffer.from(subject), keypair.privateKey);

    // Create signing certificate
    const certificates = await this.ca.createSigningCertificate(
      identityToken,
      keypair.publicKey,
      challenge
    );

    // Generate artifact signature
    const signature = crypto.signBlob(data, keypair.privateKey);

    return {
      signature: signature,
      key: {
        $case: 'x509Certificate',
        certificate: certificates[0],
      },
    };
  }

  private async getIdentityToken(): Promise<string> {
    const aggErrs = [];

    for (const provider of this.identityProviders) {
      try {
        const token = await provider.getToken();
        if (token) {
          return token;
        }
      } catch (err) {
        aggErrs.push(err);
      }
    }

    throw new InternalError({
      code: 'IDENTITY_TOKEN_READ_ERROR',
      message: 'error retrieving identity token',
      cause: aggErrs,
    });
  }
}
