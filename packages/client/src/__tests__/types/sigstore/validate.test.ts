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
import { ValidationError } from '../../../error';
import { assertValidBundle } from '../../../types/sigstore/validate';

import type {
  Bundle,
  Signature,
  X509Certificate,
} from '@sigstore/protobuf-specs';

describe('assertValidBundle', () => {
  describe('when the bundle is completely empty', () => {
    const bundle = {} as Bundle;

    it('throws an error', () => {
      expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
      });
    });

    describe('when the signature value is undefined', () => {
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
      expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
      expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
        expect(() => assertValidBundle(bundle)).toThrow(ValidationError);
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
