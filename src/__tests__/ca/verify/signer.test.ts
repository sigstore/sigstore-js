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
import { verifySignerIdentity } from '../../../ca/verify/signer';
import * as sigstore from '../../../types/sigstore';
import { x509Certificate } from '../../../x509/cert';
import { certificates } from '../../__fixtures__/certs';

describe('verifySignerIdentity', () => {
  const signingCert = x509Certificate.parse(certificates.fulcioleaf);

  const issuer = 'https://token.actions.githubusercontent.com';
  const workflowURI =
    'https://github.com/sigstore/sigstore-js/.github/workflows/publish.yml@refs/tags/v0.4.0';

  const workflowSAN: sigstore.SubjectAlternativeName = {
    type: sigstore.SubjectAlternativeNameType.URI,
    identity: {
      $case: 'value',
      value: workflowURI,
    },
  };

  const extFulcioWorkflowName: sigstore.ObjectIdentifierValuePair = {
    oid: { id: [1, 3, 6, 1, 4, 1, 57264, 1, 4] },
    value: Buffer.from('publish'),
  };

  const extFulcioRepository: sigstore.ObjectIdentifierValuePair = {
    oid: { id: [1, 3, 6, 1, 4, 1, 57264, 1, 5] },
    value: Buffer.from('sigstore/sigstore-js'),
  };

  describe('when there is a matching identity', () => {
    describe('when only one identity is specified', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: workflowSAN,
            oids: [extFulcioRepository, extFulcioWorkflowName],
          },
        ],
      };

      it('returns without error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).not.toThrowError();
      });
    });

    describe('when the matching identity has an empty OID list', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: workflowSAN,
            oids: [],
          },
        ],
      };

      it('returns without error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).not.toThrowError();
      });
    });

    describe('when the identity list contains a non-matching identity', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: workflowSAN,
            oids: [],
          },
          {
            issuer: 'https://not-the-issuer',
            san: workflowSAN,
            oids: [],
          },
        ],
      };

      it('returns without error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).not.toThrowError();
      });
    });
  });

  describe('when there is NO matching identity', () => {
    describe('when the issuer does not match', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer: 'https://not-the-issuer',
            san: workflowSAN,
            oids: [extFulcioRepository, extFulcioWorkflowName],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });

    describe('when the certificate does NOT have a SAN extension', () => {
      const signingCert = x509Certificate.parse(certificates.nosan);

      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer: 'FOO',
            san: workflowSAN,
            oids: [extFulcioRepository, extFulcioWorkflowName],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });

    describe('when the required SAN is NOT specified', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: undefined,
            oids: [],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });

    describe('when the required SAN identity is NOT specified', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: {
              type: sigstore.SubjectAlternativeNameType.URI,
              identity: undefined,
            },
            oids: [],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });

    describe('when the required SAN type is NOT specified', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: {
              type: sigstore.SubjectAlternativeNameType
                .SUBJECT_ALTERNATIVE_NAME_TYPE_UNSPECIFIED,
              identity: {
                $case: 'value',
                value: workflowURI,
              },
            },
            oids: [],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });

    describe('when the required SAN type does NOT match the certificate', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: {
              type: sigstore.SubjectAlternativeNameType.OTHER_NAME,
              identity: {
                $case: 'value',
                value: workflowURI,
              },
            },
            oids: [],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });

    describe('when the SAN value is a regexp (not supported yet)', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: {
              type: sigstore.SubjectAlternativeNameType.URI,
              identity: {
                $case: 'regexp',
                regexp: 'foo*',
              },
            },
            oids: [],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });

    describe('when a required extension is missing', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: workflowSAN,
            oids: [
              {
                oid: { id: [9, 9, 9, 9] },
                value: Buffer.from('foo'),
              },
            ],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });

    describe('when a required extension does NOT specify an OID', () => {
      const ids: sigstore.CertificateIdentities = {
        identities: [
          {
            issuer,
            san: workflowSAN,
            oids: [
              {
                oid: undefined,
                value: Buffer.from('foo'),
              },
            ],
          },
        ],
      };

      it('throws an error', () => {
        expect(() => verifySignerIdentity(signingCert, ids)).toThrowError(
          'Certificate issued to untrusted signer'
        );
      });
    });
  });
});
