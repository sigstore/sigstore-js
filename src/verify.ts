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
import { KeyLike } from 'crypto';
import * as ca from './ca/verify';
import { InvalidBundleError, VerificationError } from './error';
import * as tlog from './tlog/verify';
import * as sigstore from './types/sigstore';
import { crypto, dsse, pem } from './util';

export type KeySelector = (
  hint: string,
  trustedKeys: sigstore.PublicKey[]
) => sigstore.PublicKey | undefined;

export class Verifier {
  private trustedRoot: sigstore.TrustedRoot;
  private keySelector: KeySelector;

  constructor(trustedRoot: sigstore.TrustedRoot, keySelector?: KeySelector) {
    this.trustedRoot = trustedRoot;
    this.keySelector = keySelector || ((_, keys) => keys[0]);
  }

  // Verifies the bundle signature, the bundle's certificate chain (if present)
  // and the bundle's transparency log entries.
  public verify(
    bundle: sigstore.Bundle,
    options: sigstore.RequiredArtifactVerificationOptions,
    data?: Buffer
  ): void {
    this.verifyArtifactSignature(bundle, options, data);

    if (sigstore.isBundleWithCertificateChain(bundle)) {
      this.verifySigningCertificate(bundle, options);
    }

    this.verifyTLogEntries(bundle, options);
  }

  // Performs bundle signature verification. Determines the type of the bundle
  // content and delegates to the appropriate signature verification function.
  private verifyArtifactSignature(
    bundle: sigstore.Bundle,
    options: sigstore.ArtifactVerificationOptions,
    data?: Buffer
  ): void {
    const publicKey = this.getPublicKey(bundle, options);

    switch (bundle.content?.$case) {
      case 'messageSignature':
        if (!data) {
          throw new VerificationError(
            'no data provided for message signature verification'
          );
        }
        verifyMessageSignature(
          data,
          bundle.content.messageSignature,
          publicKey
        );
        break;
      case 'dsseEnvelope':
        verifyDSSESignature(bundle.content.dsseEnvelope, publicKey);
        break;
      default:
        throw new InvalidBundleError('no content found');
    }
  }

  // Performs verification of the bundle's certificate chain. The bundle must
  // contain a certificate chain and the options must contain the required
  // options for CA verification.
  // TODO: We've temporarily removed the requirement that the options contain
  // the list of trusted signer identities. This will be added back in a future
  // release.
  private verifySigningCertificate(
    bundle: sigstore.BundleWithCertificateChain,
    options: sigstore.RequiredArtifactVerificationOptions
  ): void {
    if (!sigstore.isCAVerificationOptions(options)) {
      throw new VerificationError(
        'no trusted certificates provided for verification'
      );
    }

    ca.verifySigningCertificate(bundle, this.trustedRoot, options);
  }

  // Performs verification of the bundle's transparency log entries. The bundle
  // must contain a list of transparency log entries.
  private verifyTLogEntries(
    bundle: sigstore.Bundle,
    options: sigstore.RequiredArtifactVerificationOptions
  ): void {
    if (!sigstore.isBundleWithVerificationMaterial(bundle)) {
      throw new InvalidBundleError('no tlog entries found');
    }

    tlog.verifyTLogEntries(bundle, this.trustedRoot, options.tlogOptions);
  }

  // Returns the public key which will be used to verify the bundle signature.
  // The public key is selected based on the verification material in the bundle
  // and the options provided.
  private getPublicKey(
    bundle: sigstore.Bundle,
    options: sigstore.ArtifactVerificationOptions
  ): KeyLike {
    // Select the key which will be used to verify the signature
    switch (bundle.verificationMaterial?.content?.$case) {
      // If the bundle contains a certificate chain, the public key is the
      // first certificate in the chain (the signing certificate)
      case 'x509CertificateChain':
        return getPublicKeyFromCertificateChain(
          bundle.verificationMaterial.content.x509CertificateChain
        );

      // If the bundle contains a public key hint, the public key is selected
      // from the list of trusted keys in the options
      case 'publicKey':
        return getPublicKeyFromHint(
          bundle.verificationMaterial.content.publicKey,
          options,
          this.keySelector
        );
      default:
        throw new InvalidBundleError('no verification material found');
    }
  }
}

// Retrieves the public key from the first certificate in the certificate chain
function getPublicKeyFromCertificateChain(
  certificateChain: sigstore.X509CertificateChain
): KeyLike {
  if (certificateChain.certificates.length === 0) {
    throw new InvalidBundleError('empty certificate chain');
  }

  const cert = pem.fromDER(certificateChain.certificates[0].rawBytes);
  return crypto.createPublicKey(cert);
}

// Retrieves the public key from the list of trusted keys in the options
// using the public key hint in the bundle
function getPublicKeyFromHint(
  publicKeyID: sigstore.PublicKeyIdentifier,
  options: sigstore.ArtifactVerificationOptions,
  keySelector: KeySelector
): KeyLike {
  if (options.signers?.$case !== 'publicKeys') {
    throw new VerificationError('no trusted keys provided for verification');
  }

  const key = keySelector(
    publicKeyID.hint,
    options.signers.publicKeys.publicKeys
  );

  if (!key?.rawBytes) {
    throw new VerificationError(
      'no public key found for signature verification'
    );
  }

  return crypto.createPublicKey(key.rawBytes);
}

// Performs signature verification for bundle containing a message signature.
// Verifies that the digest and signature found in the bundle match the
// provided data.
function verifyMessageSignature(
  data: Buffer,
  messageSignature: sigstore.MessageSignature,
  publicKey: KeyLike
): void {
  // Extract signature for message
  const { signature, messageDigest } = messageSignature;

  if (!messageDigest) {
    throw new InvalidBundleError('no message digest found');
  }

  const calculatedDigest = crypto.hash(data);
  if (!calculatedDigest.equals(messageDigest.digest)) {
    throw new VerificationError('message digest verification failed');
  }

  if (!crypto.verifyBlob(data, publicKey, signature)) {
    throw new VerificationError('artifact signature verification failed');
  }
}

// Performs signature verification for bundle containing a DSSE envelope.
// Calculates the PAE for the DSSE envelope and verifies it against the
// signature in the envelope.
function verifyDSSESignature(
  envelope: sigstore.Envelope,
  publicKey: KeyLike
): void {
  // Construct payload over which the signature was originally created
  const { payloadType, payload } = envelope;
  const data = dsse.preAuthEncoding(payloadType, payload);

  // Extract signature from DSSE envelope
  if (envelope.signatures.length === 0) {
    throw new InvalidBundleError('no signatures found in DSSE envelope');
  }

  // Only support a single signature in DSSE
  const signature = envelope.signatures[0].sig;

  if (!crypto.verifyBlob(data, publicKey, signature)) {
    throw new VerificationError('artifact signature verification failed');
  }
}
