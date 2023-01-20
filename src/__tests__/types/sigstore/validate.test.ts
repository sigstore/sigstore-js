import { InvalidBundleError } from '../../../error';
import {
  assertValidBundle,
  Bundle,
  Signature,
  X509Certificate,
} from '../../../types/sigstore';

describe('assertValidBundle', () => {
  describe('when the bundle is completely empty', () => {
    const bundle = {} as Bundle;

    it('throws an error', () => {
      expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
    });
  });

  describe('when the content type is messageSignature', () => {
    describe('when the messageDigest is undefined', () => {
      const bundle = {
        content: {
          $case: 'messageSignature',
          messageSignature: {
            signature: Buffer.from('ABC'),
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });

    describe('when the digest value is undefined', () => {
      const bundle = {
        content: {
          $case: 'messageSignature',
          messageSignature: {
            messageDigest: { digest: Buffer.alloc(0) },
            signature: Buffer.from('ABC'),
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });

    describe('when the signature value is undefined', () => {
      const bundle = {
        content: {
          $case: 'messageSignature',
          messageSignature: {
            messageDigest: { digest: Buffer.from('ABC') },
            signature: Buffer.alloc(0),
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });
  });

  describe('when the content type is dsseEnvelope', () => {
    describe('when the payload is undefined', () => {
      const bundle = {
        content: {
          $case: 'dsseEnvelope',
          dsseEnvelope: {
            payload: Buffer.alloc(0),
            payloadType: 'application/json',
            signatures: [{ sig: Buffer.from('ABC'), keyid: '' }],
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });

    describe('when there are too few signatures', () => {
      const bundle = {
        content: {
          $case: 'dsseEnvelope',
          dsseEnvelope: {
            payload: Buffer.from('ABC'),
            payloadType: 'application/json',
            signatures: [] as Signature[],
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });

    describe('when there are too many signatures', () => {
      const bundle = {
        content: {
          $case: 'dsseEnvelope',
          dsseEnvelope: {
            payload: Buffer.from('ABC'),
            payloadType: 'application/json',
            signatures: [
              { sig: Buffer.from('ABC'), keyid: '' },
              { sig: Buffer.from('ABC'), keyid: '' },
            ],
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });

    describe('when there the signature value is undefined', () => {
      const bundle = {
        content: {
          $case: 'dsseEnvelope',
          dsseEnvelope: {
            payload: Buffer.from('ABC'),
            payloadType: 'application/json',
            signatures: [{ sig: Buffer.alloc(0), keyid: '' }],
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });
  });

  describe('when the verificationMaterial is undefined', () => {
    const bundle = {
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    } as Bundle;

    it('throws an error', () => {
      expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
    });
  });

  describe('when the verificationMaterial content is undefined', () => {
    const bundle = {
      verificationMaterial: {},
      content: {
        $case: 'messageSignature',
        messageSignature: {
          messageDigest: { digest: Buffer.from('ABC') },
          signature: Buffer.from('ABC'),
        },
      },
    } as Bundle;

    it('throws an error', () => {
      expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
    });
  });

  describe('when the verificationMaterial content type is x509CertificateChain', () => {
    describe('when the certificate chain is empty', () => {
      const bundle = {
        verificationMaterial: {
          content: {
            $case: 'x509CertificateChain',
            x509CertificateChain: {
              certificates: [] as X509Certificate[],
            },
          },
        },
        content: {
          $case: 'messageSignature',
          messageSignature: {
            messageDigest: { digest: Buffer.from('ABC') },
            signature: Buffer.from('ABC'),
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });

    describe('when the certificate chain is missing a certificate', () => {
      const bundle = {
        verificationMaterial: {
          content: {
            $case: 'x509CertificateChain',
            x509CertificateChain: {
              certificates: [{ rawBytes: Buffer.alloc(0) }],
            },
          },
        },
        content: {
          $case: 'messageSignature',
          messageSignature: {
            messageDigest: { digest: Buffer.from('ABC') },
            signature: Buffer.from('ABC'),
          },
        },
      } as Bundle;

      it('throws an error', () => {
        expect(() => assertValidBundle(bundle)).toThrow(InvalidBundleError);
      });
    });
  });

  describe('when everything is valid', () => {
    const bundle = {
      verificationMaterial: {
        content: {
          $case: 'x509CertificateChain',
          x509CertificateChain: {
            certificates: [{ rawBytes: Buffer.from('FOO') }],
          },
        },
      },
      content: {
        $case: 'dsseEnvelope',
        dsseEnvelope: {
          payload: Buffer.from('ABC'),
          payloadType: 'application/json',
          signatures: [{ sig: Buffer.from('BAR'), keyid: '' }],
        },
      },
    } as Bundle;

    it('does NOT throw an error', () => {
      expect(() => assertValidBundle(bundle)).not.toThrow();
    });
  });
});
