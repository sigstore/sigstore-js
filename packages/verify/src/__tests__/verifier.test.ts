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
import { bundleFromJSON, TransparencyLogEntry } from '@sigstore/bundle';
import { crypto, json } from '@sigstore/core';
import { PublicKeyDetails } from '@sigstore/protobuf-specs';
import { fromPartial } from '@total-typescript/shoehorn';
import { generateKeyPairSync, sign } from 'crypto';
import { toSignedEntity } from '../bundle';
import { PolicyError, VerificationError } from '../error';
import { CertificateIdentity } from '../shared.types';
import { TrustMaterial, toTrustMaterial } from '../trust';
import { Verifier } from '../verifier';
import * as bundles from './__fixtures__/bundles';
import { trustedRoot } from './__fixtures__/trust';

describe('Verifier', () => {
  describe('constructor', () => {
    const trustMaterial: TrustMaterial = fromPartial({});

    it('should create a new instance', () => {
      const verifier = new Verifier(trustMaterial);
      expect(verifier).toBeDefined();
    });
  });

  describe('#verify', () => {
    const publicKey = crypto.createPublicKey(bundles.PUBLIC_KEY);

    const keys = {
      '9a76331edc1cfd3933040996615b1c06adbe6f9b4f11df4106dcceb66e3bdb1b': {
        rawBytes: publicKey.export({ type: 'spki', format: 'der' }),
        keyDetails: PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
        validFor: { start: new Date(0) },
      },
    };
    const trustMaterial = toTrustMaterial(trustedRoot, keys);
    const subject = new Verifier(trustMaterial);

    describe('when the certificate-signed message signature bundle is valid', () => {
      const subject = new Verifier(trustMaterial, {
        ctlogThreshold: 1,
        tlogThreshold: 1,
        tsaThreshold: 1,
      });
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the key-signed message signature bundle is valid', () => {
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_PUBLIC_KEY
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the certificate-signed DSSE bundle is valid', () => {
      const bundle = bundleFromJSON(
        bundles.V1.DSSE.WITH_SIGNING_CERT.TLOG_DSSE
      );
      const signedEntity = toSignedEntity(bundle);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the certificate-signed message signature v3 bundle is valid', () => {
      const subject = new Verifier(trustMaterial, {
        ctlogThreshold: 1,
        tlogThreshold: 0,
        tsaThreshold: 1,
      });
      const bundle = bundleFromJSON(
        bundles.V3.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the certificate-signed Rekor v2 DSSE bundle is valid', () => {
      const bundle = bundleFromJSON(
        bundles.V3.DSSE.WITH_SIGNING_CERT.TLOG_DSSEV002
      );
      const signedEntity = toSignedEntity(bundle);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the certificate-signed Rekor v2 DSSE bundle is valid', () => {
      const bundle = bundleFromJSON(
        bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('returns without error', () => {
        subject.verify(signedEntity);
      });
    });

    describe('when the a matching policy is specified', () => {
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);
      const policy = {
        subjectAlternativeName: Buffer.from(
          'YnJpYW5AZGVoYW1lci5jb20=',
          'base64'
        ).toString(),
        extensions: {
          issuer: 'https://github.com/login/oauth',
        },
      } satisfies CertificateIdentity;

      it('returns without error', () => {
        subject.verify(signedEntity, policy);
      });
    });

    describe('when the a non-matching policy is specified', () => {
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_PUBLIC_KEY
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);
      const policy = {
        subjectAlternativeName: 'foo@bar.com',
        extensions: {},
      } satisfies CertificateIdentity;

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity, policy)).toThrowWithCode(
          PolicyError,
          'UNTRUSTED_SIGNER_ERROR'
        );
      });
    });

    describe('when the bundle contains duplicate TLog entries', () => {
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );

      // Add a duplicate tlog entry
      bundle.verificationMaterial.tlogEntries.push({
        ...bundle.verificationMaterial.tlogEntries[0],
      });

      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'TIMESTAMP_ERROR'
        );
      });
    });

    describe('when the bundle repeats a single inclusion-proof tlog entry', () => {
      // A proof-only entry (no inclusion promise) produces no tlog timestamp,
      // so duplicating it is not caught by the timestamp duplicate check. The
      // tlog counting itself has to reject the repeat, otherwise N copies of
      // one entry would satisfy an N-of-N tlog threshold.
      const subject = new Verifier(trustMaterial, {
        tlogThreshold: 2,
        timestampThreshold: 1,
      });
      const bundle = bundleFromJSON(
        bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
      );

      bundle.verificationMaterial.tlogEntries.push({
        ...bundle.verificationMaterial.tlogEntries[0],
      });

      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'TLOG_ERROR'
        );
      });
    });

    describe('when proof-only entries have unauthenticated metadata changes', () => {
      it('rejects a single entry when two entries are required', () => {
        const bundle = bundleFromJSON(
          bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
        );
        const subject = new Verifier(trustMaterial, { tlogThreshold: 2 });

        expect(() =>
          subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
        ).toThrow('expected 2 tlog entries, got 1');
      });

      it.each(['547662', '0', '9007199254740993'])(
        'rejects a duplicate with top-level logIndex %s',
        (logIndex) => {
          const bundle = bundleFromJSON(
            bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
          );
          const subject = new Verifier(trustMaterial, { tlogThreshold: 2 });
          const entry = bundle.verificationMaterial.tlogEntries[0];
          bundle.verificationMaterial.tlogEntries.push({ ...entry, logIndex });

          expect(() =>
            subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
          ).toThrow('duplicate tlog entry');
        }
      );

      it('accepts a single entry with different global and proof-local indices', () => {
        const bundle = bundleFromJSON(
          bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
        );
        bundle.verificationMaterial.tlogEntries[0].logIndex = '123456789';

        expect(() =>
          subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
        ).not.toThrow();
      });

      it('rejects duplicates with equivalent proof-local index encodings', () => {
        const bundle = bundleFromJSON(
          bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
        );
        const entry = bundle.verificationMaterial.tlogEntries[0];
        const subject = new Verifier(trustMaterial, { tlogThreshold: 2 });
        bundle.verificationMaterial.tlogEntries.push({
          ...entry,
          logIndex: '547662',
          inclusionProof: {
            ...entry.inclusionProof!,
            logIndex: '0547661',
          },
        });

        expect(() =>
          subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
        ).toThrow('duplicate tlog entry');
      });

      it.each(['unknown', 'another trusted log', 'the same key hint'])(
        'rejects a duplicate claiming to come from %s',
        (log) => {
          const bundle = bundleFromJSON(
            bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
          );
          const entry = bundle.verificationMaterial.tlogEntries[0];
          const sameKeyHint = Buffer.from(entry.logId.keyId);
          sameKeyHint[4] ^= 0xff;
          bundle.verificationMaterial.tlogEntries.push({
            ...entry,
            logId: {
              keyId:
                log === 'unknown'
                  ? Buffer.alloc(32)
                  : log === 'another trusted log'
                    ? trustMaterial.tlogs[0].logID
                    : sameKeyHint,
            },
          });
          const subject = new Verifier(trustMaterial, { tlogThreshold: 2 });

          expect(() =>
            subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
          ).toThrowWithCode(VerificationError, 'TLOG_INCLUSION_PROOF_ERROR');
        }
      );
    });

    describe('when counting authenticated tlog bodies', () => {
      function createLog() {
        const { publicKey, privateKey } = generateKeyPairSync('ed25519');
        const logID = crypto.digest(
          'sha256',
          publicKey.export({ type: 'spki', format: 'der' })
        );
        const authority = {
          logID,
          publicKey,
          baseURL: 'https://test-log.example.com',
          validFor: { start: new Date(0), end: new Date('2100-01-01') },
        };
        return { authority, privateKey };
      }

      function createEntries(
        log: ReturnType<typeof createLog>,
        bodies: Buffer[]
      ): TransparencyLogEntry[] {
        const template = bundleFromJSON(
          bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
        ).verificationMaterial.tlogEntries[0];
        const leaves = bodies.map((body) =>
          crypto.digest('sha256', Buffer.from([0]), body)
        );
        const root = crypto.digest('sha256', Buffer.from([1]), ...leaves);
        const note = `test-log.example.com\n2\n${root.toString('base64')}\n`;
        const signature = Buffer.concat([
          log.authority.logID.subarray(0, 4),
          sign(null, Buffer.from(note), log.privateKey),
        ]);
        const envelope = `${note}\n\u2014 test-log.example.com ${signature.toString('base64')}\n`;

        return bodies.map((body, index) => ({
          ...template,
          logId: { keyId: log.authority.logID },
          logIndex: String(index),
          canonicalizedBody: body,
          inclusionProof: {
            logIndex: String(index),
            treeSize: '2',
            rootHash: root,
            hashes: [leaves[1 - index]],
            checkpoint: { envelope },
          },
        }));
      }

      it('rejects identical bodies at different authenticated positions in the same log', () => {
        const bundle = bundleFromJSON(
          bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
        );
        const log = createLog();
        const body =
          bundle.verificationMaterial.tlogEntries[0].canonicalizedBody;
        bundle.verificationMaterial.tlogEntries = createEntries(log, [
          body,
          body,
        ]);
        const material = { ...trustMaterial, tlogs: [log.authority] };
        const subject = new Verifier(material, { tlogThreshold: 2 });

        expect(() =>
          subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
        ).toThrow('duplicate tlog entry');
      });

      it('counts identical bodies from different authenticated logs separately', () => {
        const bundle = bundleFromJSON(
          bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
        );
        const logs = [createLog(), createLog()];
        const body =
          bundle.verificationMaterial.tlogEntries[0].canonicalizedBody;
        bundle.verificationMaterial.tlogEntries = logs.map(
          (log) => createEntries(log, [body, body])[0]
        );
        const material = {
          ...trustMaterial,
          tlogs: logs.map((log) => log.authority),
        };
        const subject = new Verifier(material, { tlogThreshold: 2 });

        expect(() =>
          subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
        ).not.toThrow();
      });

      it('counts different authenticated bodies in the same log separately', () => {
        const bundle = bundleFromJSON(
          bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
        );
        const log = createLog();
        const body =
          bundle.verificationMaterial.tlogEntries[0].canonicalizedBody;
        bundle.verificationMaterial.tlogEntries = createEntries(log, [
          body,
          Buffer.concat([body, Buffer.from('\n')]),
        ]);
        const material = { ...trustMaterial, tlogs: [log.authority] };
        const subject = new Verifier(material, { tlogThreshold: 2 });

        expect(() =>
          subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
        ).not.toThrow();
      });

      it.each(['promise-only', 'proof-and-promise'])(
        'rejects identical bodies with %s inclusion at different indices',
        (inclusion) => {
          const bundle = bundleFromJSON(
            bundles.V3.MESSAGE_SIGNATURE.TLOG_HASHEDREKORDV002
          );
          const log = createLog();
          const body =
            bundle.verificationMaterial.tlogEntries[0].canonicalizedBody;
          const entries = createEntries(log, [body, body]);
          for (const entry of entries) {
            const payload = {
              body: body.toString('base64'),
              integratedTime: Number(entry.integratedTime),
              logIndex: Number(entry.logIndex),
              logID: entry.logId.keyId.toString('hex'),
            };
            entry.inclusionPromise = {
              signedEntryTimestamp: sign(
                null,
                Buffer.from(json.canonicalize(payload)),
                log.privateKey
              ),
            };
            if (inclusion === 'promise-only') {
              entry.inclusionProof = undefined;
            }
          }
          bundle.verificationMaterial.tlogEntries = entries;
          const material = { ...trustMaterial, tlogs: [log.authority] };
          const subject = new Verifier(material, { tlogThreshold: 2 });

          expect(() =>
            subject.verify(toSignedEntity(bundle, bundles.ARTIFACT))
          ).toThrow('duplicate tlog entry');
        }
      );
    });

    describe('when the tlog timestamp threshold is not met', () => {
      const subject = new Verifier(trustMaterial, { tlogThreshold: 2 });
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'TLOG_ERROR'
        );
      });
    });

    describe('when the tlog entry has no inclusion promise', () => {
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );

      bundle.verificationMaterial.tlogEntries[0].inclusionPromise = undefined;

      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'TLOG_MISSING_INCLUSION_ERROR'
        );
      });
    });

    describe('when the timestamp threshold is not met', () => {
      const subject = new Verifier(trustMaterial, { timestampThreshold: 3 });
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'TIMESTAMP_ERROR'
        );
      });
    });

    describe('when the ctlog threshold is not met', () => {
      const subject = new Verifier(trustMaterial, { ctlogThreshold: 2 });
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );
      const signedEntity = toSignedEntity(bundle, bundles.ARTIFACT);

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'CERTIFICATE_ERROR'
        );
      });
    });

    describe('when the bundle signature cannot be verified', () => {
      const bundle = bundleFromJSON(
        bundles.V1.MESSAGE_SIGNATURE.WITH_SIGNING_CERT
      );
      const signedEntity = toSignedEntity(
        bundle,
        Buffer.from('not the artifact')
      );

      it('throws an error', () => {
        expect(() => subject.verify(signedEntity)).toThrowWithCode(
          VerificationError,
          'SIGNATURE_ERROR'
        );
      });
    });
  });
});
