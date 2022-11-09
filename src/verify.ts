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
import { KeyObject } from 'crypto';
import { VerificationError } from './error';
import { TLog } from './tlog';
import {
  verifyTLogBodies,
  verifyTLogIntegratedTime,
  verifyTLogSET,
} from './tlog/verify';
import {
  Bundle,
  Envelope,
  MessageSignature,
  X509CertificateChain,
} from './types/bundle';
import { crypto, dsse, pem } from './util';

export type GetPublicKeyFunc = (keyId: string) => Promise<string | undefined>;

export interface VerifyOptions {
  tlog: TLog;
  tlogKeys: Record<string, KeyObject>;
  getPublicKey?: GetPublicKeyFunc;
}

export class Verifier {
  private tlog: TLog;
  private tlogKeys: Record<string, KeyObject>;
  private getExternalPublicKey: GetPublicKeyFunc;

  constructor(options: VerifyOptions) {
    this.tlog = options.tlog;
    this.tlogKeys = options.tlogKeys;
    this.getExternalPublicKey =
      options.getPublicKey || (() => Promise.resolve(undefined));
  }

  public async verifyOffline(bundle: Bundle, data?: Buffer): Promise<void> {
    const publicKey = await this.getPublicKey(bundle);

    verifyArtifactSignature(bundle, publicKey, data);
    verifyTLogSET(bundle, this.tlogKeys);
    verifyTLogBodies(bundle);
    verifyTLogIntegratedTime(bundle);
  }

  public async getPublicKey(bundle: Bundle): Promise<string> {
    let publicKey: string | undefined;

    switch (bundle.verificationMaterial?.content?.$case) {
      case 'x509CertificateChain':
        publicKey = getSigningCertificate(
          bundle.verificationMaterial.content.x509CertificateChain
        );
        break;
      case 'publicKey':
        publicKey = await this.getExternalPublicKey(
          bundle.verificationMaterial.content.publicKey.hint
        );
        break;
      default:
        throw new VerificationError('No verification material found');
    }

    if (!publicKey) {
      throw new VerificationError(
        'No public key found for signature verification'
      );
    }

    return publicKey;
  }
}

// Performs bundle signature verification. Determines the type of the bundle
// content and delegates to the appropriate signature verification function.
function verifyArtifactSignature(
  bundle: Bundle,
  publicKey: string,
  data?: Buffer
): void {
  switch (bundle.content?.$case) {
    case 'messageSignature':
      if (!data) {
        throw new VerificationError(
          'No data provided for message signature verification'
        );
      }
      verifyMessageSignature(bundle.content.messageSignature, publicKey, data);
      break;
    case 'dsseEnvelope':
      verifyDSSESignature(bundle.content.dsseEnvelope, publicKey);
      break;
    default:
      throw new VerificationError('Bundle is invalid');
  }
}

// Performs signature verification for bundle containing a message signature.
// Verifies the signature found in the bundle against the provided data.
function verifyMessageSignature(
  messageSignature: MessageSignature,
  publicKey: string,
  data: Buffer
): void {
  // Extract signature for message
  const signature = messageSignature.signature;

  if (!crypto.verifyBlob(data, publicKey, signature)) {
    throw new VerificationError('Artifact signature verification failed');
  }
}

// Performs signature verification for bundle containing a DSSE envelope.
// Calculates the PAE for the DSSE envelope and verifies it against the
// signature in the envelope.
function verifyDSSESignature(envelope: Envelope, publicKey: string): void {
  // Construct payload over which the signature was originally created
  const { payloadType, payload } = envelope;
  const data = dsse.preAuthEncoding(payloadType, payload);

  // Extract signature from DSSE envelope
  if (envelope.signatures.length < 1) {
    throw new VerificationError('No signatures found in DSSE envelope');
  }

  // Only support a single signature in DSSE
  const signature = envelope.signatures[0].sig;

  if (!crypto.verifyBlob(data, publicKey, signature)) {
    throw new VerificationError('Artifact signature verification failed');
  }
}

// Extracts the signing certificate from the bundle and formats it as a
// PEM-encoded string.
function getSigningCertificate(
  chain: X509CertificateChain
): string | undefined {
  const signingCert = chain.certificates[0];
  return signingCert ? pem.fromDER(signingCert.rawBytes) : undefined;
}
