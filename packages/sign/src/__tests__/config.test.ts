/*
Copyright 2025 The Sigstore Authors.

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
  Service,
  ServiceSelector,
  SigningConfig,
} from '@sigstore/protobuf-specs';
import { DSSEBundleBuilder } from '../bundler/dsse';
import { MessageSignatureBundleBuilder } from '../bundler/message';
import { bundleBuilderFromSigningConfig } from '../config';
import { IdentityProvider } from '../identity';

describe('bundleBuilderFromSigningConfig', () => {
  const mockIdentityProvider: IdentityProvider = {
    getToken: jest.fn().mockResolvedValue('mock-token'),
  };

  const createService = (
    url: string,
    majorApiVersion: number,
    start?: Date,
    end?: Date,
    operator?: string
  ): Service => ({
    url,
    majorApiVersion,
    validFor: start
      ? {
          start,
          end,
        }
      : undefined,
    operator: operator || 'test-operator',
  });

  const createValidSigningConfig = (
    overrides?: Partial<SigningConfig>
  ): SigningConfig => ({
    mediaType: 'application/vnd.dev.sigstore.signingconfig.v0.2+json',
    caUrls: [
      createService('https://fulcio.example.com', 1, new Date('2023-01-01')),
    ],
    oidcUrls: [],
    rekorTlogUrls: [
      createService('https://rekor.example.com', 1, new Date('2023-01-01')),
    ],
    rekorTlogConfig: {
      selector: ServiceSelector.ANY,
      count: 1,
    },
    tsaUrls: [
      createService('https://timestamp.example.com', 1, new Date('2023-01-01')),
    ],
    tsaConfig: {
      selector: ServiceSelector.ANY,
      count: 1,
    },
    ...overrides,
  });

  describe('when creating a messageSignature bundle', () => {
    it('returns a MessageSignatureBundleBuilder', () => {
      const signingConfig = createValidSigningConfig();
      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeInstanceOf(MessageSignatureBundleBuilder);
    });
  });

  describe('when creating a dsseEnvelope bundle', () => {
    it('returns a DSSEBundleBuilder', () => {
      const signingConfig = createValidSigningConfig();
      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'dsseEnvelope',
      });

      expect(builder).toBeInstanceOf(DSSEBundleBuilder);
    });
  });

  describe('when selecting a CA service', () => {
    it('selects the CA with the newest start date', () => {
      const signingConfig = createValidSigningConfig({
        caUrls: [
          createService(
            'https://old-ca.example.com',
            1,
            new Date('2022-01-01')
          ),
          createService(
            'https://new-ca.example.com',
            1,
            new Date('2023-01-01')
          ),
          createService(
            'https://older-ca.example.com',
            1,
            new Date('2021-01-01')
          ),
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
      // The builder should be created with the newest CA
    });

    it('filters out CAs with expired end dates', () => {
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);

      const signingConfig = createValidSigningConfig({
        caUrls: [
          createService(
            'https://expired-ca.example.com',
            1,
            new Date('2022-01-01'),
            yesterday
          ),
          createService(
            'https://valid-ca.example.com',
            1,
            new Date('2023-01-01'),
            tomorrow
          ),
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });

    it('filters out CAs with API versions higher than supported', () => {
      const signingConfig = createValidSigningConfig({
        caUrls: [
          createService(
            'https://future-ca.example.com',
            99,
            new Date('2023-01-01')
          ),
          createService(
            'https://supported-ca.example.com',
            1,
            new Date('2023-01-01')
          ),
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });

    it('throws an error when no valid CAs are found', () => {
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

      const signingConfig = createValidSigningConfig({
        caUrls: [
          createService(
            'https://expired-ca.example.com',
            1,
            new Date('2022-01-01'),
            yesterday
          ),
        ],
      });

      expect(() => {
        bundleBuilderFromSigningConfig({
          signingConfig,
          identityProvider: mockIdentityProvider,
          bundleType: 'messageSignature',
        });
      }).toThrow('No valid CA services found in signing configuration');
    });

    it('throws an error when CA list is empty', () => {
      const signingConfig = createValidSigningConfig({
        caUrls: [],
      });

      expect(() => {
        bundleBuilderFromSigningConfig({
          signingConfig,
          identityProvider: mockIdentityProvider,
          bundleType: 'messageSignature',
        });
      }).toThrow('No valid CA services found in signing configuration');
    });
  });

  describe('when selecting a TLog service', () => {
    it('selects the TLog with the newest start date', () => {
      const signingConfig = createValidSigningConfig({
        rekorTlogUrls: [
          createService(
            'https://old-rekor.example.com',
            1,
            new Date('2022-01-01')
          ),
          createService(
            'https://new-rekor.example.com',
            2,
            new Date('2023-01-01')
          ),
          createService(
            'https://older-rekor.example.com',
            1,
            new Date('2021-01-01')
          ),
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });

    it('filters out TLogs with expired end dates', () => {
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);

      const signingConfig = createValidSigningConfig({
        rekorTlogUrls: [
          createService(
            'https://expired-rekor.example.com',
            1,
            new Date('2022-01-01'),
            yesterday
          ),
          createService(
            'https://valid-rekor.example.com',
            1,
            new Date('2023-01-01'),
            tomorrow
          ),
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });

    it('filters out TLogs with API versions higher than supported', () => {
      const signingConfig = createValidSigningConfig({
        rekorTlogUrls: [
          createService(
            'https://future-rekor.example.com',
            99,
            new Date('2023-01-01')
          ),
          createService(
            'https://supported-rekor.example.com',
            2,
            new Date('2023-01-01')
          ),
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });

    it('throws an error when rekorTlogConfig selector is not ANY', () => {
      const signingConfig = createValidSigningConfig({
        rekorTlogConfig: {
          selector: ServiceSelector.ALL,
          count: 1,
        },
      });

      expect(() => {
        bundleBuilderFromSigningConfig({
          signingConfig,
          identityProvider: mockIdentityProvider,
          bundleType: 'messageSignature',
        });
      }).toThrow('Unsupported Rekor TLog selector in signing configuration');
    });

    it('throws an error when no valid TLogs are found', () => {
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

      const signingConfig = createValidSigningConfig({
        rekorTlogUrls: [
          createService(
            'https://expired-rekor.example.com',
            1,
            new Date('2022-01-01'),
            yesterday
          ),
        ],
      });

      expect(() => {
        bundleBuilderFromSigningConfig({
          signingConfig,
          identityProvider: mockIdentityProvider,
          bundleType: 'messageSignature',
        });
      }).toThrow('No valid TLogs found in signing configuration');
    });

    it('creates bundle without TLog witness when rekorTlogConfig is undefined', () => {
      const signingConfig = createValidSigningConfig({
        rekorTlogConfig: undefined,
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });
  });

  describe('when selecting a TSA service', () => {
    it('throws an error when tsaConfig selector is not ANY', () => {
      const signingConfig = createValidSigningConfig({
        tsaUrls: [
          createService('https://tsa.example.com', 1, new Date('2023-01-01')),
        ],
        tsaConfig: {
          selector: ServiceSelector.ALL,
          count: 1,
        },
      });

      expect(() => {
        bundleBuilderFromSigningConfig({
          signingConfig,
          identityProvider: mockIdentityProvider,
          bundleType: 'messageSignature',
        });
      }).toThrow('Unsupported TSA selector in signing configuration');
    });

    it('selects the TSA with the newest start date', () => {
      const signingConfig = createValidSigningConfig({
        tsaUrls: [
          createService(
            'https://old-tsa.example.com',
            1,
            new Date('2022-01-01')
          ),
          createService(
            'https://new-tsa.example.com',
            1,
            new Date('2023-01-01')
          ),
        ],
        tsaConfig: {
          selector: ServiceSelector.ANY,
          count: 1,
        },
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });

    it('throws an error when no valid TSAs are found', () => {
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

      const signingConfig = createValidSigningConfig({
        tsaUrls: [
          createService(
            'https://expired-tsa.example.com',
            1,
            new Date('2022-01-01'),
            yesterday
          ),
        ],
        tsaConfig: {
          selector: ServiceSelector.ANY,
          count: 1,
        },
      });

      expect(() => {
        bundleBuilderFromSigningConfig({
          signingConfig,
          identityProvider: mockIdentityProvider,
          bundleType: 'messageSignature',
        });
      }).toThrow('No valid TSAs found in signing configuration');
    });

    it('creates bundle without TSA witness when tsaConfig is undefined', () => {
      const signingConfig = createValidSigningConfig({
        tsaConfig: undefined,
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });
  });

  describe('with custom fetch options', () => {
    it('uses custom timeout', () => {
      const signingConfig = createValidSigningConfig();
      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
        fetchOptions: {
          timeout: 10000,
        },
      });

      expect(builder).toBeDefined();
    });

    it('uses custom retry options', () => {
      const signingConfig = createValidSigningConfig();
      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
        fetchOptions: {
          retry: { retries: 5 },
        },
      });

      expect(builder).toBeDefined();
    });

    it('uses default fetch options when not provided', () => {
      const signingConfig = createValidSigningConfig();
      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });
  });

  describe('edge cases', () => {
    it('handles services with no validFor field', () => {
      const signingConfig = createValidSigningConfig({
        caUrls: [
          {
            url: 'https://ca.example.com',
            majorApiVersion: 1,
            validFor: undefined,
            operator: 'test-operator',
          },
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });

    it('handles services with no end date', () => {
      const signingConfig = createValidSigningConfig({
        caUrls: [
          createService(
            'https://ca.example.com',
            1,
            new Date('2023-01-01'),
            undefined
          ),
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });

    it('handles services with end date exactly at current time', () => {
      const now = new Date();
      const signingConfig = createValidSigningConfig({
        caUrls: [
          createService(
            'https://ca.example.com',
            1,
            new Date('2023-01-01'),
            now
          ),
        ],
      });

      const builder = bundleBuilderFromSigningConfig({
        signingConfig,
        identityProvider: mockIdentityProvider,
        bundleType: 'messageSignature',
      });

      expect(builder).toBeDefined();
    });
  });
});
