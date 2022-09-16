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
import {
  buildBlobBundle,
  buildDSSEBundle,
  DSSE,
  SigstoreBlobBundle,
  SigstoreDSSEBundle,
} from './bundle';
import { splitPEM } from './certificate';
import { Fulcio, Rekor } from './client';
import * as crypto from './crypto';
import * as enc from './encoding';
import { Provider } from './identity';
import { dssePreAuthEncoding, extractJWTSubject } from './util';

export interface SignOptions {
  fulcio: Fulcio;
  rekor: Rekor;
  identityProviders: Provider[];
}

interface SigCert {
  signature: string;
  certificate: string[];
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

  public async signBlob(payload: Buffer): Promise<SigstoreBlobBundle> {
    // Get signature and signing certificate for payload
    const { signature, certificate } = await this.sign(payload);

    // Calculate artifact digest
    const digest = crypto.hash(payload);

    const certificateB64 = enc.base64Encode(certificate[0]);

    // Create Rekor entry
    const entry = await this.rekor.createHashedRekordEntry({
      artifactDigest: digest,
      artifactSignature: signature,
      publicKey: certificateB64,
    });

    return buildBlobBundle(digest, signature, certificateB64, entry);
  }

  public async signAttestation(
    payload: Buffer,
    payloadType: string
  ): Promise<SigstoreDSSEBundle> {
    // Pre-authentication encoding to be signed
    const paeBuffer = dssePreAuthEncoding(payloadType, payload);

    // Get signature and signing certificate for pae
    const { signature, certificate } = await this.sign(paeBuffer);

    const dsse: DSSE = {
      payloadType,
      payload: payload.toString('base64'),
      signatures: [
        {
          keyid: '',
          sig: signature,
        },
      ],
    };

    const certificateB64 = enc.base64Encode(certificate[0]);

    const entry = await this.rekor.createIntoEntry({
      envelope: JSON.stringify(dsse),
      publicKey: certificateB64,
    });

    return buildDSSEBundle(dsse, certificateB64, entry);
  }

  private async sign(payload: Buffer): Promise<SigCert> {
    // Create emphemeral key pair
    const keypair = crypto.generateKeyPair();

    // Extract public key as base64-encoded string
    const publicKeyB64 = keypair.publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64');

    // Retrieve identity token from one of the supplied identity providers
    const identityToken = await this.getIdentityToken();

    // Extract challenge claim from OIDC token
    const subject = extractJWTSubject(identityToken);

    // Construct challenge value by encrypting subject with private key
    const challenge = crypto.signBlob(keypair.privateKey, subject);

    // Create signing certificate
    const certificate = await this.fulcio.createSigningCertificate({
      identityToken,
      publicKey: publicKeyB64,
      challenge,
    });

    // Generate artifact signature
    const signature = crypto.signBlob(keypair.privateKey, payload);

    return {
      signature,
      certificate: splitPEM(certificate),
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
