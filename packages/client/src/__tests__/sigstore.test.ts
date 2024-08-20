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
import { VerificationError } from '@sigstore/verify';
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

describe('signAttestation', () => {
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

    it('does not throw an error', async () => {
      await expect(verify(bundle, tufOptions)).resolves.toBe(undefined);
    }, 10000);
  });

  describe('when the bundle is a valid v0.1 DSSE bundle with public key', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.dsse.withPublicKey
    );
    const options: VerifyOptions = {
      ...tufOptions,
      keySelector: (hint: string) => validBundles.publicKeys[hint],
    };

    it('does not throw an error', async () => {
      await expect(verify(bundle, options)).resolves.toBe(undefined);
    });
  });

  describe('when the bundle is a valid v0.1 message signature bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v1.messageSignature.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).resolves.toBe(
        undefined
      );
    });
  });

  describe('when the bundle is a valid v0.2 message signature bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v2.messageSignature.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).resolves.toBe(
        undefined
      );
    });
  });

  describe('when the bundle is a valid v0.3 message signature bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v3.messageSignature.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).resolves.toBe(
        undefined
      );
    });
  });

  describe('when the bundle is a valid v0.3 dsse bundle with signing certificate', () => {
    const bundle: SerializedBundle = fromPartial(
      validBundles.v3.dsse.withSigningCert
    );
    const artifact = validBundles.artifact;

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).resolves.toBe(
        undefined
      );
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

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).resolves.toBe(
        undefined
      );
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

    it('does not throw an error when invoked', async () => {
      const verifier = await createVerifier(tufOptions!);
      expect(verifier.verify(bundle)).toBeUndefined();
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
});
