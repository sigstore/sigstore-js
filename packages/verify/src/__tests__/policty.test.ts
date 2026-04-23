import { PolicyError } from '../error';
import { verifyExtensions, verifySubjectAlternativeName } from '../policy';

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
