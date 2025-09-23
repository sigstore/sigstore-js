/*
Copyright 2022 The Sigstore Authors.

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
import type { SerializedBundle } from '@sigstore/bundle';
import { mockFulcio, mockRekor, mockTSA } from '@sigstore/mock';
import { VerificationError, Signer } from '@sigstore/verify';
import { fromPartial } from '@total-typescript/shoehorn';
import mocktuf, { Target } from '@tufjs/repo-mock';
import { attest, createVerifier, sign, verify } from '../sigstore';
import * as invalidBundles from './__fixtures__/bundles/invalid';
import * as validBundles from './__fixtures__/bundles/valid';
import { trustedRoot } from './__fixtures__/trust';

import path from 'path';
import type { SignOptions, VerifyOptions } from '../config';

const fulcioURL = 'https://fulcio.example.com';
const rekorURL = 'https://rekor.example.com';
const tsaURL = 'https://tsa.example.com';

const subject = 'foo@bar.com';
const oidcPayload = { sub: subject, iss: '' };
const oidc = `.${Buffer.from(JSON.stringify(oidcPayload)).toString(
  'base64'
)}.}`;

const idp = { getToken: () => Promise.resolve(oidc) };

describe('sign', () => {
  const payload = Buffer.from('Hello, world!');

  beforeEach(async () => {
    await mockFulcio({ baseURL: fulcioURL });
    await mockRekor({ baseURL: rekorURL });
    await mockTSA({ baseURL: tsaURL });
  });

  it('returns the signed bundle', async () => {
    const options: SignOptions = {
      fulcioURL,
      rekorURL,
      tsaServerURL: tsaURL,
      identityProvider: idp,
    };
    const bundle = await sign(payload, options);

    expect(bundle).toBeDefined();
    expect(bundle.messageSignature).toBeDefined();
    expect(bundle.messageSignature?.signature).toBeDefined();
    expect(bundle.messageSignature?.messageDigest).toBeDefined();

    expect(
      bundle.verificationMaterial.x509CertificateChain?.certificates
    ).toHaveLength(1);

    expect(bundle.verificationMaterial.tlogEntries).toHaveLength(1);
    expect(bundle.verificationMaterial.tlogEntries[0].kindVersion?.kind).toBe(
      'hashedrekord'
    );

    expect(
      bundle.verificationMaterial.timestampVerificationData?.rfc3161Timestamps
    ).toHaveLength(1);
  });
});

describe('signAttestation (legacy)', () => {
  const payload = Buffer.from('Hello, world!');
  const payloadType = 'text/plain';

  beforeEach(async () => {
    await mockFulcio({ baseURL: fulcioURL });
    await mockRekor({ baseURL: rekorURL });
    await mockTSA({ baseURL: tsaURL });
  });

  it('returns the signed bundle', async () => {
    const options: SignOptions = {
      fulcioURL,
      rekorURL,
      tsaServerURL: tsaURL,
      identityProvider: idp,
      legacyCompatibility: true,
    };
    const bundle = await attest(payload, payloadType, options);
    expect(bundle).toBeDefined();
    expect(bundle.dsseEnvelope?.payloadType).toBe(payloadType);
    expect(bundle.dsseEnvelope?.payload).toBe(payload.toString('base64'));
    expect(bundle.dsseEnvelope?.signatures).toHaveLength(1);

    expect(
      bundle.verificationMaterial.x509CertificateChain?.certificates
    ).toHaveLength(1);

    expect(bundle.verificationMaterial.tlogEntries).toHaveLength(1);
    expect(bundle.verificationMaterial.tlogEntries[0].kindVersion?.kind).toBe(
      'intoto'
    );

    expect(
      bundle.verificationMaterial.timestampVerificationData?.rfc3161Timestamps
    ).toHaveLength(1);
  });
});

describe('signAttestation (non-legacy)', () => {
  const payload = Buffer.from('Hello, world!');
  const payloadType = 'text/plain';

  beforeEach(async () => {
    await mockFulcio({ baseURL: fulcioURL });
    await mockRekor({ baseURL: rekorURL });
    await mockTSA({ baseURL: tsaURL });
  });

  it('returns the signed bundle', async () => {
    const options: SignOptions = {
      fulcioURL,
      rekorURL,
      tsaServerURL: tsaURL,
      identityProvider: idp,
      retry: 0,
      timeout: 0,
    };
    const bundle = await attest(payload, payloadType, options);
    expect(bundle).toBeDefined();
    expect(bundle.dsseEnvelope?.payloadType).toBe(payloadType);
    expect(bundle.dsseEnvelope?.payload).toBe(payload.toString('base64'));
    expect(bundle.dsseEnvelope?.signatures).toHaveLength(1);

    expect(bundle.verificationMaterial.certificate).toBeDefined();

    expect(bundle.verificationMaterial.tlogEntries).toHaveLength(1);
    expect(bundle.verificationMaterial.tlogEntries[0].kindVersion?.kind).toBe(
      'dsse'
    );

    expect(
      bundle.verificationMaterial.timestampVerificationData?.rfc3161Timestamps
    ).toHaveLength(1);
  });
});

describe('#verify', () => {
  let tufRepo: ReturnType<typeof mocktuf> | undefined;
  let tufOptions: VerifyOptions | undefined;

  const trustedRootJSON = JSON.stringify(trustedRoot);
  const target: Target = {
    name: 'trusted_root.json',
    content: Buffer.from(trustedRootJSON),
  };

  beforeEach(() => {
    tufRepo = mocktuf(target, { metadataPathPrefix: '' });
    tufOptions = {
      tufMirrorURL: tufRepo.baseURL,
      tufCachePath: tufRepo.cachePath,
      tufRootPath: path.join(tufRepo.cachePath, 'root.json'),
      certificateIssuer: 'https://github.com/login/oauth',
    };
  });

  afterEach(() => tufRepo?.teardown());

  describe('when the bundle is a valid v0.1 DSSE bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.dsse.withSigningCert
    );

    it('returns a Signer object', async () => {
      const result = await verify(bundle, tufOptions);
      expect(result).toBeDefined();
      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
      expect(result).toHaveProperty('identity');
    }, 10000);
  });

  describe('when the bundle is a valid v0.1 DSSE bundle with public key', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.dsse.withPublicKey
    );
    const options: VerifyOptions = {
      ...tufOptions,
      keySelector: (hint: string) => validBundles.publicKeys[hint],
      retry: 0,
      timeout: 0,
    };

    it('returns a Signer object', async () => {
      const result = await verify(bundle, options);
      expect(result).toBeDefined();
      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
    });
  });

  describe('when the bundle is a valid v0.1 message signature bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.messageSignature.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('returns a Signer object', async () => {
      const result = await verify(bundle, artifact, tufOptions);
      expect(result).toBeDefined();
      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
      expect(result).toHaveProperty('identity');
    });
  });

  describe('when the bundle is a valid v0.2 message signature bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v2.messageSignature.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('returns a Signer object', async () => {
      const result = await verify(bundle, artifact, tufOptions);
      expect(result).toBeDefined();
      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
      expect(result).toHaveProperty('identity');
    });
  });

  describe('when the bundle is a valid v0.3 message signature bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v3.messageSignature.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('returns a Signer object', async () => {
      const result = await verify(bundle, artifact, tufOptions);
      expect(result).toBeDefined();
      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
      expect(result).toHaveProperty('identity');
    });
  });

  describe('when the bundle is a valid v0.3 dsse bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v3.dsse.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('returns a Signer object', async () => {
      const result = await verify(bundle, artifact, tufOptions);
      expect(result).toBeDefined();
      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
      expect(result).toHaveProperty('identity');
    });
  });

  describe('when there is a signature mismatch', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.messageSignature.withSigningCert
    );
    const artifact = Buffer.from('');

    it('throws an error', async () => {
      await expect(
        verify(bundle, artifact, tufOptions)
      ).rejects.toThrowWithCode(VerificationError, 'SIGNATURE_ERROR');
    });
  });

  describe('when tlog timestamp is outside the validity period of the certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      invalidBundles.v1.messageSignature.invalidExpiredCert
    );
    const artifact = validBundles.artifact;

    it('throws an error', async () => {
      await expect(
        verify(bundle, artifact, tufOptions)
      ).rejects.toThrowWithCode(VerificationError, 'CERTIFICATE_ERROR');
    });
  });

  describe('when the bundle is newer then v0.3', () => {
    // Check a theoretical v0.4 bundle that is the same shape as a v0.3 bundle
    const bundle: SerializedBundle = fromPartial({
      ...validBundles.v3.messageSignature.withSigningCert,
    });
    bundle.mediaType = 'application/vnd.dev.sigstore.bundle+json;version=0.4';

    const artifact = validBundles.artifact;

    it('returns a Signer object', async () => {
      const result = await verify(bundle, artifact, tufOptions);
      expect(result).toBeDefined();
      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
      expect(result).toHaveProperty('identity');
    });
  });
});

describe('#verify - Signer object structure and properties', () => {
  let tufRepo: ReturnType<typeof mocktuf> | undefined;
  let tufOptions: VerifyOptions | undefined;

  const trustedRootJSON = JSON.stringify(trustedRoot);
  const target: Target = {
    name: 'trusted_root.json',
    content: Buffer.from(trustedRootJSON),
  };

  beforeEach(() => {
    tufRepo = mocktuf(target, { metadataPathPrefix: '' });
    tufOptions = {
      tufMirrorURL: tufRepo.baseURL,
      tufCachePath: tufRepo.cachePath,
      tufRootPath: path.join(tufRepo.cachePath, 'root.json'),
      certificateIssuer: 'https://github.com/login/oauth',
    };
  });

  afterEach(() => tufRepo?.teardown());

  describe('when verifying a DSSE bundle with certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.dsse.withSigningCert
    );

    it('returns a Signer with a valid key object', async () => {
      const result = await verify(bundle, tufOptions);
      expect(result).toMatchObject({
        key: expect.any(Object),
        identity: expect.any(Object),
      });

      // Verify the key is a proper crypto.KeyObject
      expect(result.key).toHaveProperty('asymmetricKeyType');
      expect(typeof result.key.export).toBe('function');
    });

    it('returns a Signer with certificate identity information', async () => {
      const result = await verify(bundle, tufOptions);
      expect(result.identity).toBeDefined();

      // The identity should have either subjectAlternativeName or extensions
      expect(
        result.identity?.subjectAlternativeName ||
        result.identity?.extensions
      ).toBeDefined();
    });

  });

  describe('when verifying a message signature bundle', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.messageSignature.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('returns a Signer object with key and identity', async () => {
      const result = await verify(bundle, artifact, tufOptions);

      expect(result).toMatchObject({
        key: expect.any(Object),
        identity: expect.any(Object),
      });
    });

    it('returns a key that can be used for cryptographic operations', async () => {
      const result = await verify(bundle, artifact, tufOptions);

      // Verify we can export the public key
      expect(() => {
        result.key.export({ format: 'pem', type: 'spki' });
      }).not.toThrow();
    });
  });

  describe('when verifying with public key', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.dsse.withPublicKey
    );
    const options: VerifyOptions = {
      ...tufOptions,
      keySelector: (hint: string) => validBundles.publicKeys[hint],
    };

    it('returns a Signer with key', async () => {
      const result = await verify(bundle, options);

      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
    });
  });
});

describe('#createVerifier', () => {
  let tufRepo: ReturnType<typeof mocktuf> | undefined;
  let tufOptions: VerifyOptions | undefined;

  const trustedRootJSON = JSON.stringify(trustedRoot);
  const target: Target = {
    name: 'trusted_root.json',
    content: Buffer.from(trustedRootJSON),
  };

  beforeEach(() => {
    tufRepo = mocktuf(target, { metadataPathPrefix: '' });
    tufOptions = {
      tufMirrorURL: tufRepo.baseURL,
      tufCachePath: tufRepo.cachePath,
      tufRootPath: path.join(tufRepo.cachePath, 'root.json'),
    };
  });

  afterEach(() => tufRepo?.teardown());

  it('returns an object', async () => {
    const verifier = await createVerifier(tufOptions!);
    expect(verifier).toBeInstanceOf(Object);
  });

  describe('when the bundle is valid', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.dsse.withSigningCert
    );

    it('returns a Signer object when invoked', async () => {
      const verifier = await createVerifier(tufOptions!);
      const result = verifier.verify(bundle);
      expect(result).toBeDefined();
      expect(result).toHaveProperty('key');
      expect(result.key).toBeDefined();
      expect(result).toHaveProperty('identity');
    });
  });

  describe('when the bundle is invalid', () => {
    const bundle: SerializedBundle = fromPartial(
      invalidBundles.v1.dsse.invalidBadSignature
    );

    it('throws an error when invoked', async () => {
      const verifier = await createVerifier(tufOptions!);
      expect(() => {
        verifier.verify(bundle);
      }).toThrowWithCode(VerificationError, 'TLOG_BODY_ERROR');
    });
  });

  describe('#createVerifier - BundleVerifier.verify Signer return tests', () => {
    describe('when verifying valid bundles', () => {
      const bundle: SerializedBundle = fromPartial(
        validBundles.v1.dsse.withSigningCert
      );

      it('BundleVerifier.verify returns Signer with proper structure', async () => {
        const verifier = await createVerifier(tufOptions!);
        const result = verifier.verify(bundle);

        expect(result).toMatchObject({
          key: expect.any(Object),
          identity: expect.any(Object),
        });

        // Test the Signer type properties
        expect(result.key).toHaveProperty('asymmetricKeyType');
      });


      it('BundleVerifier.verify throws error for invalid bundle but still returns Signer type when valid', async () => {
        const validVerifier = await createVerifier(tufOptions!);
        const invalidBundle: SerializedBundle = fromPartial(
          invalidBundles.v1.dsse.invalidBadSignature
        );

        // Test that invalid bundles still throw errors
        expect(() => {
          validVerifier.verify(invalidBundle);
        }).toThrowWithCode(VerificationError, 'TLOG_BODY_ERROR');

        // But valid bundles should return Signer
        const result = validVerifier.verify(bundle);
        expect(result).toMatchObject({
          key: expect.any(Object),
          identity: expect.any(Object),
        });
      });
    });

    describe('when verifying with data payload', () => {
      const bundle: SerializedBundle = fromPartial(
        validBundles.v1.messageSignature.withSigningCert
      );
      const artifact = validBundles.artifact;

      it('BundleVerifier.verify with data returns proper Signer', async () => {
        const verifier = await createVerifier(tufOptions!);
        const result = verifier.verify(bundle, artifact);

        expect(result).toMatchObject({
          key: expect.any(Object),
          identity: expect.any(Object),
        });

        // Verify identity contains expected certificate information
        expect(result.identity).toBeDefined();
        if (result.identity) {
          expect(
            result.identity.subjectAlternativeName || result.identity.extensions
          ).toBeDefined();
        }
      });

      it('BundleVerifier.verify returns Signer with working cryptographic key', async () => {
        const verifier = await createVerifier(tufOptions!);
        const result = verifier.verify(bundle, artifact);

        // Ensure the key can be exported and used
        expect(() => {
          const exported = result.key.export({ format: 'pem', type: 'spki' });
          expect(typeof exported).toBe('string');
          expect(exported).toContain('-----BEGIN PUBLIC KEY-----');
        }).not.toThrow();
      });
    });
  });
});
