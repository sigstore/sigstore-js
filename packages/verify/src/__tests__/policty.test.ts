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
