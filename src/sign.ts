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
import { Fulcio, Rekor } from './client';
import { generateKeyPair, hash, signBlob } from './crypto';
import { Provider } from './identity';
import { base64Encode, extractJWTSubject } from './util';

export interface SignOptions {
  fulcio: Fulcio;
  rekor: Rekor;
  identityProviders: Provider[];
}

export interface SigstoreBundle {
  attestationType: 'attestation/blob';
  attestation: {
    payloadHash: string;
    payloadHashAlgorithm: string;
    signature: string;
  };
  certificate: string;
  signedEntryTimestamp: string;
  integratedTime: number;
  logIndex: number;
  logID: string;
}

export class Signer {
  private fulcio: Fulcio;
  private rekor: Rekor;

  private identityProviders: Provider[] = [];

  constructor(options: SignOptions) {
    this.fulcio = options.fulcio;
    this.rekor = options.rekor;
    this.identityProviders = options.identityProviders;
  }

  public async sign(payload: Buffer): Promise<SigstoreBundle> {
    // Create emphemeral key pair
    const keypair = generateKeyPair();

    // Extract public key as base64-encoded string
    const publicKeyB64 = keypair.publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64');

    // Retrieve identity token from one of the supplied identity providers
    const identityToken = await this.getIdentityToken();

    // Extract challenge claim from OIDC token
    const subject = extractJWTSubject(identityToken);

    // Construct challenge value by encrypting subject with private key
    const challenge = signBlob(keypair.privateKey, subject);

    // Create signing certificate
    const certificate = await this.fulcio.createSigningCertificate({
      identityToken,
      publicKey: publicKeyB64,
      challenge,
    });
    const b64Certificate = base64Encode(certificate);

    // Generate artifact signature
    const signature = signBlob(keypair.privateKey, payload);

    // Calculate artifact digest
    const digest = hash(payload);

    // Create Rekor entry
    const entry = await this.rekor.createHashedRekordEntry({
      artifactDigest: digest,
      artifactSignature: signature,
      publicKey: b64Certificate,
    });

    console.error(`Created entry at index ${entry.logIndex}, available at`);
    console.error(
      `https://rekor.sigstore.dev/api/v1/log/entries/${entry.uuid}`
    );

    const bundle: SigstoreBundle = {
      attestationType: 'attestation/blob',
      attestation: {
        payloadHash: digest,
        payloadHashAlgorithm: 'sha256',
        signature: signature,
      },
      certificate: b64Certificate,
      signedEntryTimestamp: entry.verification.signedEntryTimestamp,
      integratedTime: entry.integratedTime,
      logID: entry.logID,
      logIndex: entry.logIndex,
    };

    return bundle;
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

    throw new Error(`Identity token providers failed: ${aggErrs}`);
  }
}
