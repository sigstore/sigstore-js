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
import crypto from 'crypto';
import fs from 'fs';
import { VerificationError } from '../error';
import * as sigstore from '../types/sigstore';
import { Verifier } from '../verify';
import bundles from './__fixtures__/bundles';

describe('Verifier', () => {
  const trustedRootJSON = JSON.parse(
    fs
      .readFileSync(require.resolve('../../store/trusted_root.json'))
      .toString('utf8')
  );
  const trustedRoot: sigstore.TrustedRoot =
    sigstore.TrustedRoot.fromJSON(trustedRootJSON);

  const options: sigstore.RequiredArtifactVerificationOptions = {
    ctlogOptions: {
      disable: false,
      threshold: 1,
      detachedSct: false,
    },
    tlogOptions: {
      disable: false,
      threshold: 1,
      performOnlineVerification: false,
    },
  };

  const subject = new Verifier(trustedRoot);

  describe('#verify', () => {
    describe('when bundle type is messageSignature', () => {
      const payload = bundles.signature.artifact;

      describe('when the key comes from the bundle', () => {
        const bundle = sigstore.bundleFromJSON(
          bundles.signature.valid.withSigningCert
        );

        describe('when the signature and the cert match', () => {
          it('does NOT throw an error', () => {
            expect(() =>
              subject.verify(bundle, options, payload)
            ).not.toThrow();
          });
        });

        describe('when the signature and the cert do NOT match', () => {
          it('throws an error', () => {
            expect(() =>
              subject.verify(bundle, options, Buffer.from(''))
            ).toThrow(VerificationError);
          });
        });

        describe('when original artifact is missing', () => {
          it('throws an error', () => {
            expect(() => subject.verify(bundle, options, undefined)).toThrow(
              VerificationError
            );
          });
        });

        describe('when the trusted signers is malformed', () => {
          const optionsWithSigners: sigstore.RequiredArtifactVerificationOptions =
            {
              ...options,
              signers: {
                $case: 'publicKeys',
                publicKeys: {
                  publicKeys: [],
                },
              },
            };

          it('throws an error', () => {
            expect(() =>
              subject.verify(bundle, optionsWithSigners, payload)
            ).toThrow(VerificationError);
          });
        });
      });

      describe('when the key comes from the trusted signers', () => {
        const bundle = sigstore.bundleFromJSON(
          bundles.signature.valid.withPublicKey
        );

        const publicKey = crypto.createPublicKey(bundles.signature.publicKey);

        const optionsWithSigners: sigstore.RequiredArtifactVerificationOptions =
          {
            ...options,
            signers: {
              $case: 'publicKeys',
              publicKeys: {
                publicKeys: [
                  {
                    keyDetails:
                      sigstore.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                    rawBytes: publicKey.export({ format: 'der', type: 'spki' }),
                  },
                ],
              },
            },
          };

        describe('when the key is available', () => {
          describe('when the signature and the cert match', () => {
            it('does NOT throw an error', () => {
              expect(() =>
                subject.verify(bundle, optionsWithSigners, payload)
              ).not.toThrow();
            });
          });

          describe('when the payload digest does not match the value in the bundle', () => {
            it('throws an error', () => {
              expect(() =>
                subject.verify(bundle, optionsWithSigners, Buffer.from(''))
              ).toThrow(VerificationError);
            });
          });

          describe('when the bundle signature is incorrect', () => {
            const bundle = sigstore.bundleFromJSON(
              bundles.signature.invalid.badSignature
            );

            it('throws an error', () => {
              expect(() =>
                subject.verify(bundle, optionsWithSigners, payload)
              ).toThrow(VerificationError);
            });
          });
        });

        describe('when the key is NOT available', () => {
          it('throws an error', () => {
            expect(() => subject.verify(bundle, options, payload)).toThrow(
              VerificationError
            );
          });
        });
      });
    });

    describe('when bundle type is dsseEnvelope', () => {
      describe('when the key comes from the bundle', () => {
        describe('when the signature and the cert match', () => {
          const bundle = sigstore.bundleFromJSON(
            bundles.dsse.valid.withSigningCert
          );

          it('does NOT throw an error', () => {
            expect(() => subject.verify(bundle, options)).not.toThrow();
          });
        });

        describe('when the signature and the cert do NOT match', () => {
          const bundle = sigstore.bundleFromJSON(
            bundles.dsse.invalid.badSignature
          );
          it('throws an error', () => {
            expect(() => subject.verify(bundle, options)).toThrow(
              VerificationError
            );
          });
        });
      });

      describe('when the key comes from the trusted signers', () => {
        const publicKey = crypto.createPublicKey(bundles.dsse.publicKey);

        const optionsWithSigners: sigstore.RequiredArtifactVerificationOptions =
          {
            ...options,
            signers: {
              $case: 'publicKeys',
              publicKeys: {
                publicKeys: [
                  {
                    keyDetails:
                      sigstore.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                    rawBytes: publicKey.export({ format: 'der', type: 'spki' }),
                  },
                ],
              },
            },
          };

        describe('when the signature and the cert match', () => {
          const bundle = sigstore.bundleFromJSON(
            bundles.dsse.valid.withPublicKey
          );

          it('does NOT throw an error', () => {
            expect(() =>
              subject.verify(bundle, optionsWithSigners)
            ).not.toThrow();
          });
        });

        describe('when the signature and the cert do NOT match', () => {
          const bundle = sigstore.bundleFromJSON(
            bundles.dsse.invalid.badSignature
          );

          it('throws an error', () => {
            expect(() => subject.verify(bundle, optionsWithSigners)).toThrow(
              VerificationError
            );
          });
        });

        describe('when the trusted key is malformed', () => {
          const bundle = sigstore.bundleFromJSON(
            bundles.dsse.valid.withPublicKey
          );

          const optionsWithSigners: sigstore.RequiredArtifactVerificationOptions =
            {
              ...options,
              signers: {
                $case: 'publicKeys',
                publicKeys: {
                  publicKeys: [
                    {
                      keyDetails:
                        sigstore.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                    },
                  ],
                },
              },
            };

          it('throws an error', () => {
            expect(() => subject.verify(bundle, optionsWithSigners)).toThrow(
              VerificationError
            );
          });
        });
      });
    });
  });
});
