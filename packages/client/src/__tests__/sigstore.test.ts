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
import { TUFError } from '@sigstore/tuf';
import mocktuf, { Target } from '@tufjs/repo-mock';
import nock from 'nock';
import { PolicyError, VerificationError } from '../error';
import { SignOptions, attest, sign, tuf, verify } from '../sigstore';
import { SignatureMaterial, SignerFunc } from '../types/signature';
import { TrustedRoot } from '../types/sigstore';
import { crypto, pem } from '../util';
import bundles from './__fixtures__/bundles';
import { trustedRoot } from './__fixtures__/trust';

import type { VerifyOptions } from '../config';

// Fulcio Data
const fulcioURL = 'http://localhost:8282';
const jwtPayload = {
  iss: 'https://example.com',
  sub: 'foo@bar.com',
};
const jwt = `.${Buffer.from(JSON.stringify(jwtPayload)).toString('base64')}.`;

const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----`;
const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----`;

const certResponse = {
  signedCertificateEmbeddedSct: {
    chain: { certificates: [leafCertificate, rootCertificate] },
  },
};

// Callback Signer Data
const sigMaterial: SignatureMaterial = {
  signature: Buffer.from('signature'),
  certificates: undefined,
  key: { value: 'key', id: 'hint' },
};

// TSA Data
const tsaServerURL = 'http://localhost:8080';
const timestamp = Buffer.from('timestamp');

// Rekor Data
const rekorURL = 'http://localhost:8181';
const uuid = '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6';

const proposedEntry = {
  apiVersion: '0.0.1',
  kind: 'foo',
};

const rekorEntry = {
  [uuid]: {
    body: Buffer.from(JSON.stringify(proposedEntry)).toString('base64'),
    integratedTime: 1654015743,
    logID: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
    logIndex: 2513258,
    verification: {
      signedEntryTimestamp:
        'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
    },
  },
};

describe('sign', () => {
  const payload = Buffer.from('payload');

  beforeEach(() => {
    nock(tsaServerURL)
      .matchHeader('Content-Type', 'application/json')
      .post('/api/v1/timestamp')
      .reply(201, timestamp);

    nock(rekorURL)
      .matchHeader('Accept', 'application/json')
      .matchHeader('Content-Type', 'application/json')
      .post('/api/v1/log/entries')
      .reply(201, rekorEntry);
  });

  describe('when using keyless signing', () => {
    const opts: SignOptions = {
      fulcioURL,
      tsaServerURL,
      rekorURL,
      identityToken: jwt,
    };

    beforeEach(() => {
      nock(fulcioURL)
        .matchHeader('Content-Type', 'application/json')
        .post('/api/v2/signingCert')
        .reply(200, certResponse);
    });

    it('returns a valid bundle', async () => {
      const bundle = await sign(payload, opts);

      expect(bundle).toBeTruthy();
      expect(bundle.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );
      expect(bundle.dsseEnvelope).toBeUndefined();

      expect(bundle.messageSignature).toBeTruthy();
      expect(bundle.messageSignature?.messageDigest?.algorithm).toEqual(
        'SHA2_256'
      );
      expect(bundle.messageSignature?.messageDigest?.digest).toEqual(
        crypto.hash(payload).toString('base64')
      );
      expect(bundle.messageSignature?.signature).toBeTruthy();

      const vm = bundle.verificationMaterial;
      expect(vm).toBeTruthy();
      expect(vm.publicKey).toBeUndefined();
      expect(vm.x509CertificateChain?.certificates).toHaveLength(1);
      expect(vm.x509CertificateChain?.certificates[0].rawBytes).toEqual(
        pem.toDER(leafCertificate).toString('base64')
      );
      expect(vm.timestampVerificationData?.rfc3161Timestamps).toHaveLength(1);
      expect(
        vm.timestampVerificationData?.rfc3161Timestamps[0].signedTimestamp
      ).toEqual(timestamp.toString('base64'));
      expect(vm.tlogEntries).toHaveLength(1);
      expect(vm.tlogEntries[0].logIndex).toEqual(
        rekorEntry[uuid].logIndex.toString()
      );
      expect(vm.tlogEntries[0].logId.keyId).toEqual(
        Buffer.from(rekorEntry[uuid].logID, 'hex').toString('base64')
      );
      expect(vm.tlogEntries[0].integratedTime).toEqual(
        rekorEntry[uuid].integratedTime.toString()
      );
      expect(vm.tlogEntries[0].kindVersion?.kind).toEqual(proposedEntry.kind);
      expect(vm.tlogEntries[0].kindVersion?.version).toEqual(
        proposedEntry.apiVersion
      );
      expect(vm.tlogEntries[0].inclusionProof).toBeUndefined();
      expect(vm.tlogEntries[0].inclusionPromise.signedEntryTimestamp).toEqual(
        rekorEntry[uuid].verification.signedEntryTimestamp
      );
      expect(vm.tlogEntries[0].canonicalizedBody).toEqual(
        Buffer.from(JSON.stringify(proposedEntry)).toString('base64')
      );
    });
  });

  describe('when using callback signing', () => {
    const signer = jest
      .fn()
      .mockResolvedValue(sigMaterial) satisfies SignerFunc;

    const opts: SignOptions = {
      tsaServerURL,
      rekorURL,
      signer,
      identityToken: jwt, // TODO: Fix, we shouldn't need this here
    };

    it('returns a valid bundle', async () => {
      const bundle = await sign(payload, opts);

      expect(bundle).toBeTruthy();
      expect(bundle.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );
      expect(bundle.dsseEnvelope).toBeUndefined();

      expect(bundle.messageSignature).toBeTruthy();
      expect(bundle.messageSignature?.messageDigest?.algorithm).toEqual(
        'SHA2_256'
      );
      expect(bundle.messageSignature?.messageDigest?.digest).toEqual(
        crypto.hash(payload).toString('base64')
      );
      expect(bundle.messageSignature?.signature).toBeTruthy();

      const vm = bundle.verificationMaterial;
      expect(vm).toBeTruthy();
      expect(vm.x509CertificateChain).toBeUndefined();
      expect(vm.publicKey?.hint).toEqual(sigMaterial.key.id);

      expect(vm.timestampVerificationData?.rfc3161Timestamps).toHaveLength(1);
      expect(
        vm.timestampVerificationData?.rfc3161Timestamps[0].signedTimestamp
      ).toEqual(timestamp.toString('base64'));
      expect(vm.tlogEntries).toHaveLength(1);
      expect(vm.tlogEntries[0].logIndex).toEqual(
        rekorEntry[uuid].logIndex.toString()
      );
      expect(vm.tlogEntries[0].logId.keyId).toEqual(
        Buffer.from(rekorEntry[uuid].logID, 'hex').toString('base64')
      );
      expect(vm.tlogEntries[0].integratedTime).toEqual(
        rekorEntry[uuid].integratedTime.toString()
      );
      expect(vm.tlogEntries[0].kindVersion?.kind).toEqual(proposedEntry.kind);
      expect(vm.tlogEntries[0].kindVersion?.version).toEqual(
        proposedEntry.apiVersion
      );
      expect(vm.tlogEntries[0].inclusionProof).toBeUndefined();
      expect(vm.tlogEntries[0].inclusionPromise.signedEntryTimestamp).toEqual(
        rekorEntry[uuid].verification.signedEntryTimestamp
      );
      expect(vm.tlogEntries[0].canonicalizedBody).toEqual(
        Buffer.from(JSON.stringify(proposedEntry)).toString('base64')
      );
    });
  });
});

describe('attest', () => {
  const payload = Buffer.from('attestation');
  const payloadType = 'text/plain';

  beforeEach(() => {
    nock(tsaServerURL)
      .matchHeader('Content-Type', 'application/json')
      .post('/api/v1/timestamp')
      .reply(201, timestamp);

    nock(rekorURL)
      .matchHeader('Accept', 'application/json')
      .matchHeader('Content-Type', 'application/json')
      .post('/api/v1/log/entries')
      .reply(201, rekorEntry);
  });

  describe('when using keyless signing', () => {
    const opts: SignOptions = {
      fulcioURL,
      tsaServerURL,
      identityToken: jwt,
      tlogUpload: false,
    };

    beforeEach(() => {
      nock(fulcioURL)
        .matchHeader('Content-Type', 'application/json')
        .post('/api/v2/signingCert')
        .reply(200, certResponse);
    });

    it('returns a valid bundle', async () => {
      const bundle = await attest(payload, payloadType, opts);

      expect(bundle).toBeTruthy();
      expect(bundle.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );
      expect(bundle.messageSignature).toBeUndefined();

      expect(bundle.dsseEnvelope?.payload).toEqual(payload.toString('base64'));
      expect(bundle.dsseEnvelope?.payloadType).toEqual(payloadType);
      expect(bundle.dsseEnvelope?.signatures).toHaveLength(1);
      expect(bundle.dsseEnvelope?.signatures[0].sig).toBeTruthy();
      expect(bundle.dsseEnvelope?.signatures[0].keyid).toEqual('');

      const vm = bundle.verificationMaterial;
      expect(vm).toBeTruthy();
      expect(vm.publicKey).toBeUndefined();
      expect(vm.x509CertificateChain?.certificates).toHaveLength(1);
      expect(vm.x509CertificateChain?.certificates[0].rawBytes).toEqual(
        pem.toDER(leafCertificate).toString('base64')
      );
      expect(vm.timestampVerificationData?.rfc3161Timestamps).toHaveLength(1);
      expect(
        vm.timestampVerificationData?.rfc3161Timestamps[0].signedTimestamp
      ).toEqual(timestamp.toString('base64'));
      expect(vm.tlogEntries).toHaveLength(0);
    });
  });

  describe('when using callback signing', () => {
    const signer = jest
      .fn()
      .mockResolvedValue(sigMaterial) satisfies SignerFunc;

    const opts: SignOptions = {
      tsaServerURL,
      tlogUpload: false,
      signer,
      identityToken: jwt, // TODO: Fix, we shouldn't need this here
    };

    it('returns a valid bundle', async () => {
      const bundle = await attest(payload, payloadType, opts);

      expect(bundle).toBeTruthy();
      expect(bundle.mediaType).toEqual(
        'application/vnd.dev.sigstore.bundle+json;version=0.1'
      );
      expect(bundle.messageSignature).toBeUndefined();

      expect(bundle.dsseEnvelope?.payload).toEqual(payload.toString('base64'));
      expect(bundle.dsseEnvelope?.payloadType).toEqual(payloadType);
      expect(bundle.dsseEnvelope?.signatures).toHaveLength(1);
      expect(bundle.dsseEnvelope?.signatures[0].sig).toBeTruthy();
      expect(bundle.dsseEnvelope?.signatures[0].keyid).toEqual(
        sigMaterial.key.id
      );

      const vm = bundle.verificationMaterial;
      expect(vm).toBeTruthy();
      expect(vm.x509CertificateChain).toBeUndefined();
      expect(vm.publicKey?.hint).toEqual(sigMaterial.key.id);

      expect(vm.timestampVerificationData?.rfc3161Timestamps).toHaveLength(1);
      expect(
        vm.timestampVerificationData?.rfc3161Timestamps[0].signedTimestamp
      ).toEqual(timestamp.toString('base64'));
      expect(vm.tlogEntries).toHaveLength(0);
    });
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
    const bundle = bundles.signature.valid.withSigningCert;
    const artifact = bundles.signature.artifact;

    it('does not throw an error', async () => {
      await expect(verify(bundle, artifact, tufOptions)).resolves.toBe(
        undefined
      );
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
});

describe('tuf', () => {
  let tufRepo: ReturnType<typeof mocktuf> | undefined;
  let options: VerifyOptions | undefined;

  beforeEach(() => {
    tufRepo = mocktuf(target, { metadataPathPrefix: '' });
    options = {
      tufMirrorURL: tufRepo.baseURL,
      tufCachePath: tufRepo.cachePath,
    };
  });

  afterEach(() => tufRepo?.teardown());

  const target: Target = {
    name: 'foo',
    content: 'bar',
  };

  describe('getTarget', () => {
    describe('when the target exists', () => {
      it('returns the target', async () => {
        const result = await tuf.getTarget(target.name, options);
        expect(result).toEqual(target.content);
      });
    });

    describe('when the target does NOT exist', () => {
      it('throws an error', async () => {
        await expect(tuf.getTarget('baz', options)).rejects.toThrowWithCode(
          TUFError,
          'TUF_FIND_TARGET_ERROR'
        );
      });
    });
  });
});
