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
import { InvalidBundleError, VerificationError } from '../error';
import { TLogClient } from '../tlog';
import { Bundle, bundleFromJSON } from '../types/bundle';
import { Verifier } from '../verify';
import bundles, { tlogKeys } from './__fixtures__/bundles';

describe('Verifier', () => {
  const rekorBaseURL = 'http://localhost:8002';
  const tlog = new TLogClient({ rekorBaseURL });

  const subject = new Verifier({ tlog, tlogKeys });

  describe('#verifyOffline', () => {
    describe('when the bundle is malformed', () => {
      it('throws an error', async () => {
        await expect(subject.verifyOffline({} as Bundle)).rejects.toThrow(
          InvalidBundleError
        );
      });
    });

    describe('when bundle type is messageSignature', () => {
      const payload = Buffer.from('hello, world!');

      describe('when the key comes from the bundle', () => {
        const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);

        describe('when the signature and the cert match', () => {
          it('does NOT throw an error', async () => {
            await expect(
              subject.verifyOffline(bundle, payload)
            ).resolves.toBeUndefined();
          });
        });

        describe('when the signature and the cert do NOT match', () => {
          it('throws an error', async () => {
            await expect(
              subject.verifyOffline(bundle, Buffer.from(''))
            ).rejects.toThrow(VerificationError);
          });
        });

        describe('when original artifact is missing', () => {
          it('throws an error', async () => {
            await expect(
              subject.verifyOffline(bundle, undefined)
            ).rejects.toThrow(VerificationError);
          });
        });
      });

      describe('when the key comes from the findKey callback', () => {
        const bundle = bundleFromJSON(bundles.signature.valid.withPublicKey);

        describe('when the key is available', () => {
          const getPublicKey = () =>
            Promise.resolve(bundles.signature.publicKey);

          const subject = new Verifier({
            tlog,
            tlogKeys,
            getPublicKey,
          });

          describe('when the signature and the cert match', () => {
            it('does NOT throw an error', async () => {
              await expect(
                subject.verifyOffline(bundle, payload)
              ).resolves.toBeUndefined();
            });
          });

          describe('when the signature and the cert do NOT match', () => {
            it('throws an error', async () => {
              await expect(
                subject.verifyOffline(bundle, Buffer.from(''))
              ).rejects.toThrow(VerificationError);
            });
          });
        });

        describe('when the key is NOT available', () => {
          describe('when the signature and the cert match', () => {
            it('throws an error', async () => {
              await expect(
                subject.verifyOffline(bundle, payload)
              ).rejects.toThrow(VerificationError);
            });
          });
        });
      });
    });

    describe('when bundle type is dsseEnvelope', () => {
      describe('when the key comes from the bundle', () => {
        describe('when the signature and the cert match', () => {
          const bundle = bundleFromJSON(bundles.dsse.valid.withSigningCert);

          it('does NOT throw an error', async () => {
            await expect(
              subject.verifyOffline(bundle)
            ).resolves.toBeUndefined();
          });
        });

        describe('when the signature and the cert do NOT match', () => {
          const bundle = bundleFromJSON(bundles.dsse.invalid.badSignature);
          it('throws an error', async () => {
            await expect(subject.verifyOffline(bundle)).rejects.toThrow(
              VerificationError
            );
          });
        });

        describe('when the signature is missing', () => {
          const bundle = bundleFromJSON(bundles.dsse.invalid.noSignature);
          it('throws an error', async () => {
            await expect(subject.verifyOffline(bundle)).rejects.toThrow(
              InvalidBundleError
            );
          });
        });
      });

      describe('when the key comes from the findKey callback', () => {
        const getPublicKey = () => Promise.resolve(bundles.dsse.publicKey);

        const subject = new Verifier({
          tlog,
          tlogKeys,
          getPublicKey,
        });

        describe('when the signature and the cert match', () => {
          const bundle = bundleFromJSON(bundles.dsse.valid.withPublicKey);

          it('does NOT throw an error', async () => {
            await expect(
              subject.verifyOffline(bundle)
            ).resolves.toBeUndefined();
          });
        });

        describe('when the signature and the cert do NOT match', () => {
          const bundle = bundleFromJSON(bundles.dsse.invalid.badSignature);

          it('throws an error', async () => {
            await expect(subject.verifyOffline(bundle)).rejects.toThrow(
              VerificationError
            );
          });
        });
      });
    });
  });
});
