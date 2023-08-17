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
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import type { SerializedBundle } from '@sigstore/bundle';
import { mockFulcio, mockRekor, mockTSA } from '@sigstore/mock';
import { TrustedRoot } from '@sigstore/protobuf-specs';
import { fromPartial } from '@total-typescript/shoehorn';
import mocktuf, { Target } from '@tufjs/repo-mock';
import { PolicyError, VerificationError } from '../error';
import { attest, createVerifier, sign, verify } from '../sigstore';
import bundles from './__fixtures__/bundles/v01';
import bundlesV02 from './__fixtures__/bundles/v02';
import { trustedRoot } from './__fixtures__/trust';

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

  it('constructs the Signer with the correct options', async () => {
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

  beforeEach(() => {
    tufRepo = mocktuf(target, { metadataPathPrefix: '' });
    tufOptions = {
      tufMirrorURL: tufRepo.baseURL,
      tufCachePath: tufRepo.cachePath,
    };
  });

  afterEach(() => tufRepo?.teardown());

  const trustedRootJSON = JSON.stringify(TrustedRoot.toJSON(trustedRoot));
  const target: Target = {
    name: 'trusted_root.json',
    content: Buffer.from(trustedRootJSON),
  };

  describe('when everything in the bundle is valid', () => {
    const bundle = bundles.dsse.valid.withSigningCert;

    it('does not throw an error', async () => {
      await expect(verify(bundle, tufOptions)).resolves.toBe(undefined);
    });
  });

  describe('when there is a signature mismatch', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = Buffer.from('');
    it('throws an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).rejects.toThrowError(
        VerificationError
      );
    });
  });

  describe('when the bundle was signed by a trusted identity', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    const options: VerifyOptions = {
      certificateIssuer: 'https://github.com/login/oauth',
      certificateIdentityEmail: Buffer.from(
        'YnJpYW5AZGVoYW1lci5jb20=',
        'base64'
      ).toString('ascii'),
      certificateOIDs: {
        '1.3.6.1.4.1.57264.1.1': 'https://github.com/login/oauth',
      },
      ...tufOptions,
    };

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, options)).resolves.toBeUndefined();
    });
  });

  describe('when an issuer is specified w/o a SAN identity', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    const options: VerifyOptions = {
      certificateIssuer: 'https://github.com/login/oauth',
      ...tufOptions,
    };

    it('throws an error', async () => {
      await expect(verify(bundle, artifact, options)).rejects.toThrowError(
        PolicyError
      );
    });
  });

  describe('when the bundle was signed by an untrusted identity', () => {
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    const options: VerifyOptions = {
      certificateIssuer: 'https://github.com/login/oauth',
      certificateIdentityURI: 'https://foo.bar/',
      ...tufOptions,
    };

    it('throws an error', async () => {
      await expect(verify(bundle, artifact, options)).rejects.toThrowError(
        PolicyError
      );
    });
  });

  describe('when tlog timestamp is outside the validity period of the certificate', () => {
    const bundle = bundles.signature.invalid.expiredCert;
    const artifact = bundles.signature.artifact;

    it('throws an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).rejects.toThrowError(
        VerificationError
      );
    });
  });

  describe('when the bundle is a v0.2 bundle', () => {
    const bundle = bundlesV02.signature.valid.withSigningCert;
    const artifact = bundlesV02.signature.artifact;

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).resolves.toBe(
        undefined
      );
    });
  });

  describe('when the bundle is newer then v0.2', () => {
    // Check a theoretical v0.3 bundle that is the same shape as a v0.2 bundle
    const bundle = { ...bundlesV02.signature.valid.withSigningCert };
    bundle.mediaType = 'application/vnd.dev.sigstore.bundle+json;version=0.3';

    const artifact = bundlesV02.signature.artifact;

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

  const trustedRootJSON = JSON.stringify(TrustedRoot.toJSON(trustedRoot));
  const target: Target = {
    name: 'trusted_root.json',
    content: Buffer.from(trustedRootJSON),
  };

  beforeEach(() => {
    tufRepo = mocktuf(target, { metadataPathPrefix: '' });
    tufOptions = {
      tufMirrorURL: tufRepo.baseURL,
      tufCachePath: tufRepo.cachePath,
    };
  });

  afterEach(() => tufRepo?.teardown());

  it('returns a object', async () => {
    const verifier = await createVerifier(tufOptions!);
    expect(verifier).toBeInstanceOf(Object);
  });

  describe('when the bundle is valid', () => {
    const bundle: SerializedBundle = fromPartial(
      bundles.dsse.valid.withSigningCert
    );

    it('does not throw an error when invoked', async () => {
      const verifier = await createVerifier(tufOptions!);
      expect(verifier.verify(bundle)).toBeUndefined();
    });
  });

  describe('when the bundle is invalid', () => {
    const bundle: SerializedBundle = fromPartial(
      bundles.dsse.invalid.badSignature
    );

    it('throws an error when invoked', async () => {
      const verifier = await createVerifier(tufOptions!);
      expect(() => {
        verifier.verify(bundle);
      }).toThrowError(VerificationError);
    });
  });
});
