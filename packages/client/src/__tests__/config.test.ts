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
import { SubjectAlternativeNameType } from '@sigstore/protobuf-specs';
import {
  DSSEBundleBuilder,
  MessageSignatureBundleBuilder,
} from '@sigstore/sign';
import {
  VerifyOptions,
  artifactVerificationOptions,
  createBundleBuilder,
} from '../config';

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

    describe('when an OIDC issuer is provided', () => {
      const options = {
        oidcIssuer: 'https://example.com',
        oidcClientID: 'abc',
      };
      it('returns a MessageSignatureBundleBuilder', () => {
        const bundler = createBundleBuilder(bundleType, options);
        expect(bundler).toBeInstanceOf(MessageSignatureBundleBuilder);
      });
    });

    describe('when no OIDC options are provided', () => {
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

describe('artifactVerificationOptions', () => {
  describe('when no certificate issuer is provided', () => {
    it('returns the default options', () => {
      const result = artifactVerificationOptions({});
      expect(result.ctlogOptions.disable).toBe(false);
      expect(result.ctlogOptions.threshold).toBe(1);
      expect(result.ctlogOptions.detachedSct).toBe(false);
      expect(result.tlogOptions.disable).toBe(false);
      expect(result.tlogOptions.threshold).toBe(1);
      expect(result.tlogOptions.performOnlineVerification).toBe(false);
      expect(result.signers).toBeUndefined();
    });
  });

  describe('when certificate identity email is provided', () => {
    const options: VerifyOptions = {
      certificateIssuer: 'example.com',
      certificateIdentityEmail: 'test@example.com',
      certificateOIDs: {
        '1.2.3.4': 'value1',
        '5.6.7.8': 'value2',
      },
      ctLogThreshold: 2,
      tlogThreshold: 3,
    };

    it('returns the expected options', () => {
      const result = artifactVerificationOptions(options);
      expect(result.ctlogOptions.disable).toBe(false);
      expect(result.ctlogOptions.threshold).toBe(2);
      expect(result.ctlogOptions.detachedSct).toBe(false);
      expect(result.tlogOptions.disable).toBe(false);
      expect(result.tlogOptions.threshold).toBe(3);
      expect(result.tlogOptions.performOnlineVerification).toBe(false);

      if (!result.signers) {
        throw new Error('signers is undefined');
      }

      if (
        !result.signers.$case ||
        result.signers.$case !== 'certificateIdentities'
      ) {
        throw new Error('signers.$case is not certificateIdentities');
      }

      expect(result.signers.certificateIdentities.identities.length).toBe(1);
      expect(result.signers.certificateIdentities.identities[0].issuer).toBe(
        'example.com'
      );
      expect(
        result.signers.certificateIdentities.identities[0].san
      ).toBeDefined();
      expect(result.signers.certificateIdentities.identities[0].san?.type).toBe(
        SubjectAlternativeNameType.EMAIL
      );

      if (
        result.signers.certificateIdentities.identities[0].san?.identity
          ?.$case !== 'value'
      ) {
        throw new Error(
          'signers.certificateIdentities.identities[0].san?.identity?.$case is not value'
        );
      }

      expect(
        result.signers.certificateIdentities.identities[0].san?.identity?.$case
      ).toBe('value');
      expect(
        result.signers.certificateIdentities.identities[0].san?.identity?.value
      ).toBe('test@example.com');
      expect(
        result.signers.certificateIdentities.identities[0].oids
      ).toBeDefined();
      expect(
        result.signers.certificateIdentities.identities[0].oids?.length
      ).toBe(2);
      expect(
        result.signers.certificateIdentities.identities[0].oids?.[0].oid?.id
      ).toEqual([1, 2, 3, 4]);
      expect(
        result.signers.certificateIdentities.identities[0].oids?.[0].value
      ).toEqual(Buffer.from('value1'));
      expect(
        result.signers.certificateIdentities.identities[0].oids?.[1].oid?.id
      ).toEqual([5, 6, 7, 8]);
      expect(
        result.signers.certificateIdentities.identities[0].oids?.[1].value
      ).toEqual(Buffer.from('value2'));
    });
  });

  describe('when the certificate identity URI is provided', () => {
    const options: VerifyOptions = {
      certificateIssuer: 'example.com',
      certificateIdentityURI: 'https://example.com/cert',
      certificateOIDs: {
        '1.2.3.4': 'value1',
        '5.6.7.8': 'value2',
      },
      ctLogThreshold: 0,
      tlogThreshold: 0,
    };

    it('returns the expected options', () => {
      const result = artifactVerificationOptions(options);
      expect(result.ctlogOptions.disable).toBe(true);
      expect(result.ctlogOptions.threshold).toBe(0);
      expect(result.ctlogOptions.detachedSct).toBe(false);
      expect(result.tlogOptions.disable).toBe(true);
      expect(result.tlogOptions.threshold).toBe(0);
      expect(result.tlogOptions.performOnlineVerification).toBe(false);
      expect(result.signers).toBeDefined();

      if (!result.signers) {
        throw new Error('signers is undefined');
      }

      if (
        !result.signers.$case ||
        result.signers.$case !== 'certificateIdentities'
      ) {
        throw new Error('signers.$case is not certificateIdentities');
      }

      expect(result.signers.$case).toBe('certificateIdentities');
      expect(result.signers.certificateIdentities.identities.length).toBe(1);
      expect(result.signers.certificateIdentities.identities[0].issuer).toBe(
        'example.com'
      );
      expect(
        result.signers.certificateIdentities.identities[0].san
      ).toBeDefined();
      expect(result.signers.certificateIdentities.identities[0].san?.type).toBe(
        SubjectAlternativeNameType.URI
      );
      expect(
        result.signers.certificateIdentities.identities[0].san?.identity?.$case
      ).toBe('value');

      if (
        result.signers.certificateIdentities.identities[0].san?.identity
          ?.$case !== 'value'
      ) {
        throw new Error(
          'signers.certificateIdentities.identities[0].san?.identity?.$case is not value'
        );
      }
      expect(
        result.signers.certificateIdentities.identities[0].san?.identity?.value
      ).toBe('https://example.com/cert');
      expect(
        result.signers.certificateIdentities.identities[0].oids
      ).toBeDefined();
      expect(
        result.signers.certificateIdentities.identities[0].oids?.length
      ).toBe(2);
      expect(
        result.signers.certificateIdentities.identities[0].oids?.[0].oid?.id
      ).toEqual([1, 2, 3, 4]);
      expect(
        result.signers.certificateIdentities.identities[0].oids?.[0].value
      ).toEqual(Buffer.from('value1'));
      expect(
        result.signers.certificateIdentities.identities[0].oids?.[1].oid?.id
      ).toEqual([5, 6, 7, 8]);
      expect(
        result.signers.certificateIdentities.identities[0].oids?.[1].value
      ).toEqual(Buffer.from('value2'));
    });
  });
});
