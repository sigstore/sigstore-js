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
import { verifyTLogIntegratedTime, verifyTLogSET } from './tlog/verify';
import { Bundle } from './types/bundle';
import { crypto, dsse, pem } from './util';

export interface VerifyOptions {
  tlog: TLog;
  tlogKeys: Record<string, KeyObject>;
}

export class Verifier {
  private tlog: TLog;
  private tlogKeys: Record<string, KeyObject>;

  constructor(options: VerifyOptions) {
    this.tlog = options.tlog;
    this.tlogKeys = options.tlogKeys;
  }

  public verifyOffline(bundle: Bundle, data?: Buffer): void {
    verifyArtifactSignature(bundle, data);
    verifyTLogSET(bundle, this.tlogKeys);
    verifyTLogIntegratedTime(bundle);
  }
}

// Performs bundle signature verification. Determines the type of the bundle
// content and delegates to the appropriate signature verification function.
function verifyArtifactSignature(bundle: Bundle, data?: Buffer): void {
  switch (bundle.content?.$case) {
    case 'messageSignature':
      if (!data) {
        throw new VerificationError(
          'No data provided for message signature verification'
        );
      }
      verifyMessageSignature(bundle, data);
      break;
    case 'dsseEnvelope':
      verifyDSSESignature(bundle);
      break;
    default:
      throw new VerificationError('Bundle is invalid');
  }
}

// Performs signature verification for bundle containing a message signature.
// Verifies the signature found in the bundle against the provided data.
function verifyMessageSignature(bundle: Bundle, data: Buffer): void {
  if (bundle.content?.$case !== 'messageSignature') {
    throw new VerificationError('No message signature found in bundle');
  }

  // Extract signature for message
  const signature = bundle.content.messageSignature.signature;

  // Get signing certificate containing public key
  const publicKey = getSigningCertificate(bundle);

  if (!crypto.verifyBlob(data, publicKey, signature)) {
    throw new VerificationError('Artifact signature verification failed');
  }
}

// Performs signature verification for bundle containing a DSSE envelope.
// Calculates the PAE for the DSSE envelope and verifies it against the
// signature in the envelope.
function verifyDSSESignature(bundle: Bundle): void {
  if (bundle.content?.$case !== 'dsseEnvelope') {
    throw new VerificationError('Bundle is not a DSSE envelope');
  }

  // Construct payload over which the signature was originally created
  const payloadType = bundle.content.dsseEnvelope.payloadType;
  const payload = bundle.content.dsseEnvelope.payload;
  const data = dsse.preAuthEncoding(payloadType, payload);

  // Extract signature from DSSE envelope
  if (bundle.content.dsseEnvelope.signatures.length < 1) {
    throw new VerificationError('No signatures found in DSSE envelope');
  }

  // TODO: Support multiple signatures
  const signature = bundle.content.dsseEnvelope.signatures[0].sig;

  // Get signing certificate containing public key
  const publicKey = getSigningCertificate(bundle);

  if (!crypto.verifyBlob(data, publicKey, signature)) {
    throw new VerificationError('Artifact signature verification failed');
  }
}

// Extracts the signing certificate from the bundle and formats it as a
// PEM-encoded string.
function getSigningCertificate(bundle: Bundle): string {
  if (bundle.verificationMaterial?.content?.$case !== 'x509CertificateChain') {
    throw new VerificationError('No certificate found in bundle');
  }

  const signingCert =
    bundle.verificationMaterial.content.x509CertificateChain.certificates[0];

  if (!signingCert) {
    throw new VerificationError('No certificate found in bundle');
  }

  return pem.fromDER(signingCert.rawBytes);
}
