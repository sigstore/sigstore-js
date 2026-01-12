import { PolicyError } from '../error';
import {
  verifyExtensions,
  verifyOIDs,
  verifySubjectAlternativeName,
} from '../policy';

import type { ObjectIdentifierValuePair } from '@sigstore/protobuf-specs';

describe('verifySubjectAlternativeName', () => {
  describe('when the signer identity is undefined', () => {
    it('throws an error', () => {
      expect(() =>
        verifySubjectAlternativeName('foo', undefined)
      ).toThrowWithCode(PolicyError, 'UNTRUSTED_SIGNER_ERROR');
    });
  });

  describe('when the signer identity does not match the policy', () => {
    it('throws an error', () => {
      expect(() => verifySubjectAlternativeName('foo', 'bar')).toThrowWithCode(
        PolicyError,
        'UNTRUSTED_SIGNER_ERROR'
      );
    });
  });

  describe('when the signer identity matches the policy', () => {
    it('does not throw an error', () => {
      expect(() => verifySubjectAlternativeName('foo', 'foo')).not.toThrow();
    });
  });

  describe('when the policy is a regex pattern', () => {
    it('matches as an unanchored regex', () => {
      expect(() =>
        verifySubjectAlternativeName('user@example\\.com', 'user@example.com')
      ).not.toThrow();
    });

    it('accepts a RegExp policy', () => {
      expect(() =>
        verifySubjectAlternativeName(/^user@example\.com$/, 'user@example.com')
      ).not.toThrow();
    });

    it('accepts a substring match without anchoring', () => {
      expect(() =>
        verifySubjectAlternativeName(
          'user@example\\.com',
          'evil-user@example.com'
        )
      ).not.toThrow();
    });

    it('rejects a non-matching identity with an anchored pattern', () => {
      expect(() =>
        verifySubjectAlternativeName(
          '^user@example\\.com$',
          'evil-user@example.com'
        )
      ).toThrowWithCode(PolicyError, 'UNTRUSTED_SIGNER_ERROR');
    });
  });
});

describe('verifyExtensions', () => {
  describe('when the signer extensions are undefined', () => {
    it('throws an error', () => {
      expect(() =>
        verifyExtensions({ issuer: 'foo' }, undefined)
      ).toThrowWithCode(PolicyError, 'UNTRUSTED_SIGNER_ERROR');
    });
  });

  describe('when the signer extension values are undefined', () => {
    it('throws an error', () => {
      expect(() =>
        verifyExtensions({ issuer: 'foo' }, { issuer: undefined })
      ).toThrowWithCode(PolicyError, 'UNTRUSTED_SIGNER_ERROR');
    });
  });

  describe('when the signer extensions do not match the policy', () => {
    it('throws an error', () => {
      expect(() =>
        verifyExtensions({ issuer: 'foo' }, { issuer: 'bar' })
      ).toThrowWithCode(PolicyError, 'UNTRUSTED_SIGNER_ERROR');
    });
  });

  describe('when the signer extensions match the policy', () => {
    it('does not throw an error', () => {
      expect(() =>
        verifyExtensions({ issuer: 'foo' }, { issuer: 'foo' })
      ).not.toThrow();
    });
  });
});

describe('verifyOIDs', () => {
  const makeOIDPair = (
    oid: string,
    value: string
  ): ObjectIdentifierValuePair => ({
    oid: { id: oid.split('.').map(Number) },
    value: Buffer.from(value),
  });

  describe('when the policy has no OIDs', () => {
    it('does not throw an error', () => {
      expect(() => verifyOIDs([], [])).not.toThrow();
    });
  });

  describe('when the signer OIDs are undefined', () => {
    it('throws an error', () => {
      const policyOIDs = [makeOIDPair('1.3.6.1.4.1.57264.1.9', 'foo')];

      expect(() => verifyOIDs(policyOIDs, undefined)).toThrowWithCode(
        PolicyError,
        'UNTRUSTED_SIGNER_ERROR'
      );
    });
  });

  describe('when the signer has a matching OID', () => {
    it('does not throw an error', () => {
      const oid = '1.3.6.1.4.1.57264.1.9';
      const value = 'https://github.com/foo/bar';
      const policyOIDs = [makeOIDPair(oid, value)];
      const signerOIDs = [
        makeOIDPair('1.3.6.1.4.1.57264.1.8', 'issuer-value'),
        makeOIDPair(oid, value),
      ];

      expect(() => verifyOIDs(policyOIDs, signerOIDs)).not.toThrow();
    });
  });

  describe('when a policy OID has no oid identifier', () => {
    it('throws an error', () => {
      const policyOIDs: ObjectIdentifierValuePair[] = [
        { oid: undefined, value: Buffer.from('foo') },
      ];
      const signerOIDs = [makeOIDPair('1.3.6.1.4.1.57264.1.9', 'foo')];

      expect(() => verifyOIDs(policyOIDs, signerOIDs)).toThrowWithCode(
        PolicyError,
        'UNTRUSTED_SIGNER_ERROR'
      );
    });
  });

  describe('when a signer OID has no oid identifier', () => {
    it('throws an error', () => {
      const policyOIDs = [makeOIDPair('1.3.6.1.4.1.57264.1.9', 'foo')];
      const signerOIDs: ObjectIdentifierValuePair[] = [
        { oid: undefined, value: Buffer.from('foo') },
      ];

      expect(() => verifyOIDs(policyOIDs, signerOIDs)).toThrowWithCode(
        PolicyError,
        'UNTRUSTED_SIGNER_ERROR'
      );
    });
  });

  describe('when the signer is missing the OID', () => {
    it('throws an error', () => {
      const policyOIDs = [makeOIDPair('1.3.6.1.4.1.57264.1.9', 'foo')];
      const signerOIDs = [
        makeOIDPair('1.3.6.1.4.1.57264.1.8', 'issuer-value'),
      ];

      expect(() => verifyOIDs(policyOIDs, signerOIDs)).toThrowWithCode(
        PolicyError,
        'UNTRUSTED_SIGNER_ERROR'
      );
    });
  });

  describe('when the OID matches but the value does not', () => {
    it('throws an error', () => {
      const oid = '1.3.6.1.4.1.57264.1.9';
      const policyOIDs = [makeOIDPair(oid, 'expected-value')];
      const signerOIDs = [makeOIDPair(oid, 'different-value')];

      expect(() => verifyOIDs(policyOIDs, signerOIDs)).toThrowWithCode(
        PolicyError,
        'UNTRUSTED_SIGNER_ERROR'
      );
    });
  });

  describe('when multiple OIDs are required', () => {
    it('does not throw when all match', () => {
      const policyOIDs = [
        makeOIDPair('1.3.6.1.4.1.57264.1.9', 'uri-value'),
        makeOIDPair('1.3.6.1.4.1.57264.1.12', 'repo-value'),
      ];
      const signerOIDs = [
        makeOIDPair('1.3.6.1.4.1.57264.1.9', 'uri-value'),
        makeOIDPair('1.3.6.1.4.1.57264.1.12', 'repo-value'),
        makeOIDPair('1.3.6.1.4.1.57264.1.8', 'issuer'),
      ];

      expect(() => verifyOIDs(policyOIDs, signerOIDs)).not.toThrow();
    });

    it('throws when one is missing', () => {
      const policyOIDs = [
        makeOIDPair('1.3.6.1.4.1.57264.1.9', 'uri-value'),
        makeOIDPair('1.3.6.1.4.1.57264.1.12', 'repo-value'),
      ];
      const signerOIDs = [
        makeOIDPair('1.3.6.1.4.1.57264.1.9', 'uri-value'),
      ];

      expect(() => verifyOIDs(policyOIDs, signerOIDs)).toThrowWithCode(
        PolicyError,
        'UNTRUSTED_SIGNER_ERROR'
      );
    });
  });
});
