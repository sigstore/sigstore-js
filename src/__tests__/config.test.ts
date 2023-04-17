import { SubjectAlternativeNameType } from '@sigstore/protobuf-specs';
import {
  artifactVerificationOptions,
  IdentityProviderOptions,
  identityProviders,
  VerifyOptions,
} from '../config';

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

describe('identityProvider', () => {
  describe('when no options are supplied', () => {
    const options: IdentityProviderOptions = {};

    it('returns the static IdentityProvider', async () => {
      const result = identityProviders(options);
      expect(result).toBeDefined();
      expect(result).toHaveLength(1);

      const { getToken } = result[0];
      await expect(getToken()).rejects.toThrowError();
    });
  });

  describe('when a static token is provided', () => {
    const options: IdentityProviderOptions = {
      identityToken: 'token',
    };

    it('returns the CI IdentityProvider', async () => {
      const result = identityProviders(options);
      expect(result).toBeDefined();
      expect(result).toHaveLength(1);

      const { getToken } = result[0];
      await expect(getToken()).resolves.toEqual(options.identityToken);
    });
  });

  describe('when OAuth config options are provided', () => {
    const options: IdentityProviderOptions = {
      oidcIssuer: 'https://example.com',
      oidcClientID: 'client-id',
    };

    it('returns both the CI and OAuth IdentityProviders', async () => {
      const result = identityProviders(options);
      expect(result).toBeDefined();
      expect(result).toHaveLength(2);
    });
  });
});
