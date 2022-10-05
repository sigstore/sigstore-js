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
import { Provider } from './identity';
import { Bundle, bundle, Envelope } from './types/bundle';
import { fulcio } from './types/fulcio';
import { rekor } from './types/rekor';
import { crypto, dsse, oidc, pem } from './util';

export interface SignOptions {
  fulcio: Fulcio;
  rekor: Rekor;
  identityProviders: Provider[];
}

interface SigCert {
  signature: Buffer;
  certificates: string[];
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

  public async signBlob(payload: Buffer): Promise<Bundle> {
    // Get signature and signing certificate for payload
    const { signature, certificates } = await this.sign(payload);

    // Calculate artifact digest
    const digest = crypto.hash(payload);

    const leafCertificate = certificates[0];

    // Create Rekor entry
    const proposedEntry = rekor.toProposedHashedRekordEntry(
      digest,
      signature,
      leafCertificate
    );
    const entry = await this.rekor.createEntry(proposedEntry);

    return bundle.toMessageSignatureBundle(
      digest,
      signature,
      certificates,
      entry
    );
  }

  public async signAttestation(
    payload: Buffer,
    payloadType: string
  ): Promise<Bundle> {
    // Pre-authentication encoding to be signed
    const paeBuffer = dsse.preAuthEncoding(payloadType, payload);

    // Get signature and signing certificate for pae
    const { signature, certificates } = await this.sign(paeBuffer);

    const envelope: Envelope = {
      payloadType,
      payload: payload,
      signatures: [
        {
          keyid: '',
          sig: signature,
        },
      ],
    };

    const signingCertificate = certificates[0];

    const proposedEntry = rekor.toProposedIntotoEntry(
      envelope,
      signingCertificate
    );
    const entry = await this.rekor.createEntry(proposedEntry);

    return bundle.toDSSEBundle(envelope, certificates, entry);
  }

  private async sign(payload: Buffer): Promise<SigCert> {
    // Create emphemeral key pair
    const keypair = crypto.generateKeyPair();

    // Retrieve identity token from one of the supplied identity providers
    const identityToken = await this.getIdentityToken();

    // Extract challenge claim from OIDC token
    const subject = oidc.extractJWTSubject(identityToken);

    // Construct challenge value by encrypting subject with private key
    const challenge = crypto.signBlob(Buffer.from(subject), keypair.privateKey);

    // Create signing certificate
    const certificate = await this.fulcio.createSigningCertificate(
      identityToken,
      fulcio.toCertificateRequest(keypair.publicKey, challenge)
    );

    // Generate artifact signature
    const signature = crypto.signBlob(payload, keypair.privateKey);

    return {
      signature,
      certificates: pem.split(certificate),
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

    throw new Error(`Identity token providers failed: ${aggErrs}`);
  }
}
