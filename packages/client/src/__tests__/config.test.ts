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
import {
  DSSEBundleBuilder,
  MessageSignatureBundleBuilder,
} from '@sigstore/sign';
import { VerificationError } from '@sigstore/verify';
import {
  createBundleBuilder,
  createKeyFinder,
  createVerificationPolicy,
} from '../config';
import { publicKeys } from './__fixtures__/bundles/valid';

describe('createBundleBuilder', () => {
  describe('when the bundleType is messageSignature', () => {
    const bundleType = 'messageSignature';

    describe('when a hard-coded OIDC token is provided', () => {
      const options = { identityToken: 'abc' };
      it('returns a MessageSignatureBundleBuilder', () => {
        const bundler = createBundleBuilder(bundleType, options);
        expect(bundler).toBeInstanceOf(MessageSignatureBundleBuilder);
      });
    });

    describe('when no OIDC token is provided', () => {
      it('returns a MessageSignatureBundleBuilder', () => {
        const bundler = createBundleBuilder(bundleType, {});
        expect(bundler).toBeInstanceOf(MessageSignatureBundleBuilder);
      });
    });

    describe('when Rekor is disabled', () => {
      const options = { tlogUpload: false };

      it('returns a MessageSignatureBundleBuilder', () => {
        const bundler = createBundleBuilder(bundleType, options);
        expect(bundler).toBeInstanceOf(MessageSignatureBundleBuilder);
      });
    });

    describe('when TSA is enabled', () => {
      const options = { tsaServerURL: 'https://tsa.example.com' };

      it('returns a MessageSignatureBundleBuilder', () => {
        const bundler = createBundleBuilder(bundleType, options);
        expect(bundler).toBeInstanceOf(MessageSignatureBundleBuilder);
      });
    });
  });

  describe('when the bundleType is dsseEnvelope', () => {
    const bundleType = 'dsseEnvelope';

    it('returns a MessageSignatureBundleBuilder', () => {
      const bundler = createBundleBuilder(bundleType, {});
      expect(bundler).toBeInstanceOf(DSSEBundleBuilder);
    });
  });
});

describe('createKeyFinder', () => {
  describe('when the supplied key selector finds the key', () => {
    const keyFinder = createKeyFinder(() => Object.values(publicKeys)[0]);

    it('returns the key', () => {
      const key = keyFinder('hint');
      expect(key.publicKey).toBeDefined();
      expect(key.validFor).toBeInstanceOf(Function);
    });
  });

  describe('when the supplied key selector does NOT find the key', () => {
    const keyFinder = createKeyFinder(() => undefined);

    it('throws an error', () => {
      expect(() => keyFinder('hint')).toThrowWithCode(
        VerificationError,
        'PUBLIC_KEY_ERROR'
      );
    });
  });
});

describe('createVerificationPolicy', () => {
  describe('when the options specify a certificateIdentityEmail', () => {
    const options = { certificateIdentityEmail: 'foo@bar.com' };

    it('returns a verification policy', () => {
      const policy = createVerificationPolicy(options);
      expect(policy).toBeDefined();
      expect(policy.subjectAlternativeName).toEqual(
        options.certificateIdentityEmail
      );
      expect(policy.extensions).toBeUndefined();
    });
  });

  describe('when the options specify a certificateIdentityURI', () => {
    const options = { certificateIdentityURI: 'https://foo.bar.com' };

    it('returns a verification policy', () => {
      const policy = createVerificationPolicy(options);
      expect(policy).toBeDefined();
      expect(policy.subjectAlternativeName).toEqual(
        options.certificateIdentityURI
      );
      expect(policy.extensions).toBeUndefined();
    });
  });

  describe('when the options specify a certificateIssuer', () => {
    const options = { certificateIssuer: 'https://bar.foo.com' };

    it('returns a verification policy', () => {
      const policy = createVerificationPolicy(options);
      expect(policy).toBeDefined();
      expect(policy.extensions).toBeDefined();
      expect(policy.extensions?.issuer).toEqual(options.certificateIssuer);
      expect(policy.subjectAlternativeName).toBeUndefined();
    });
  });
});
