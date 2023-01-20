import { InvalidBundleError } from '../../error';
import { WithRequired } from '../utility';
import { Bundle, VerificationMaterial } from './__generated__/sigstore_bundle';
import { MessageSignature } from './__generated__/sigstore_common';

// Sigstore bundle with all required fields populated
type ValidBundle = Bundle & {
  verificationMaterial: VerificationMaterial & {
    content: NonNullable<VerificationMaterial['content']>;
  };
  content:
    | (Extract<Bundle['content'], { $case: 'messageSignature' }> & {
        messageSignature: WithRequired<MessageSignature, 'messageDigest'>;
      })
    | Extract<Bundle['content'], { $case: 'dsseEnvelope' }>;
};

// Performs basic validation of a Sigstore bundle to ensure that all required
// fields are populated. This is not a complete validation of the bundle, but
// rather a check that the bundle is in a valid state to be processed by the
// rest of the code.
export function assertValidBundle(b: Bundle): asserts b is ValidBundle {
  // Content-related validation
  if (b.content === undefined) {
    throw new InvalidBundleError('content is undefined');
  }

  switch (b.content.$case) {
    case 'messageSignature':
      if (b.content.messageSignature.messageDigest === undefined) {
        throw new InvalidBundleError('messageDigest is undefined');
      }

      if (b.content.messageSignature.messageDigest.digest.length === 0) {
        throw new InvalidBundleError('digest is undefined');
      }

      if (b.content.messageSignature.signature.length === 0) {
        throw new InvalidBundleError('signature is undefined');
      }
      break;
    case 'dsseEnvelope':
      if (b.content.dsseEnvelope.payload.length === 0) {
        throw new InvalidBundleError('payload is undefined');
      }

      if (b.content.dsseEnvelope.signatures.length !== 1) {
        throw new InvalidBundleError(
          'dsseEnvelope must have exactly one signature'
        );
      }

      if (b.content.dsseEnvelope.signatures[0].sig.length === 0) {
        throw new InvalidBundleError('dsseEnvelope sig is undefined');
      }
      break;
  }

  // Verification material-related validation
  if (b.verificationMaterial === undefined) {
    throw new InvalidBundleError('verificationMaterial is undefined');
  }

  if (b.verificationMaterial.content === undefined) {
    throw new InvalidBundleError('verificationMaterial content is undefined');
  }

  switch (b.verificationMaterial.content.$case) {
    case 'x509CertificateChain':
      if (
        b.verificationMaterial.content.x509CertificateChain.certificates
          .length === 0
      ) {
        throw new InvalidBundleError('x509CertificateChain is empty');
      }

      b.verificationMaterial.content.x509CertificateChain.certificates.forEach(
        (cert, i) => {
          if (cert.rawBytes.length === 0) {
            throw new InvalidBundleError(
              `certificate ${i} in x509CertificateChain is empty`
            );
          }
        }
      );
      break;
  }
}
