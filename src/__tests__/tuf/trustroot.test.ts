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
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Updater } from 'tuf-js';
import { TrustedRootError } from '../../error';
import { TrustedRootFetcher } from '../../tuf/trustroot';

describe('TrustedRootFetcher', () => {
  const publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGg6Hjxt2UNiJ1kwwq5XQIIwMZnJf
VQ3bF01uZKteMdcV/3qhCmWOecoxRqwrbYTshGg9NyXcBbve6zKwZVTLeg==
-----END PUBLIC KEY-----`;

  // Set-up a directory to use as our TUF cache and write a public key to it.
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tuf-cache-test-'));
  const targetFile = path.join(tempDir, 'key.pub');
  fs.writeFileSync(targetFile, publicKey);

  afterAll(() => {
    fs.rmSync(tempDir, { recursive: true });
  });

  const caCertTarget = {
    custom: {
      sigstore: {
        uri: 'https://fulcio.sigstore.dev',
        usage: 'Fulcio',
        status: 'active',
      },
    },
  };

  const tlogKeyTarget = {
    custom: {
      sigstore: {
        uri: 'https://rekor.sigstore.dev',
        usage: 'Rekor',
        status: 'active',
      },
    },
  };

  const ctlogKeyTarget = {
    custom: {
      sigstore: {
        uri: 'https://ctfe.sigstore.dev',
        usage: 'CTFE',
        status: 'active',
      },
    },
  };

  describe('getTrustedRoot', () => {
    describe('when the targets can be retrieved', () => {
      // Dummy TUF Updater
      const tuf = {
        refresh: jest.fn(),
        findCachedTarget: jest.fn().mockReturnValue(targetFile),
        trustedSet: {
          targets: {
            signed: { targets: [caCertTarget, tlogKeyTarget, ctlogKeyTarget] },
          },
        },
      };

      const subject = new TrustedRootFetcher(tuf as unknown as Updater);

      it('assembles and returns the TrustedRoot', async () => {
        const root = await subject.getTrustedRoot();

        expect(root).toBeDefined();
        expect(root.certificateAuthorities).toHaveLength(1);
        expect(root.tlogs).toHaveLength(1);
        expect(root.ctlogs).toHaveLength(1);
        expect(root.timestampAuthorities).toHaveLength(0);

        const ca = root.certificateAuthorities[0];
        expect(ca.uri).toEqual('');
        expect(ca.certChain?.certificates).toHaveLength(1);
        expect(ca.certChain?.certificates[0].rawBytes).toBeDefined();

        const tlog = root.tlogs[0];
        expect(tlog.baseUrl).toEqual(tlogKeyTarget.custom.sigstore.uri);
        expect(tlog.publicKey?.rawBytes).toBeDefined();

        const ctlog = root.ctlogs[0];
        expect(ctlog.baseUrl).toEqual(ctlogKeyTarget.custom.sigstore.uri);
        expect(ctlog.publicKey?.rawBytes).toBeDefined();
      });
    });

    describe('when the TUF refresh throws an error', () => {
      // Dummy TUF Updater
      const tuf = {
        refresh: jest.fn().mockRejectedValue(new Error('oops')),
        trustedSet: {
          targets: {
            signed: { targets: [caCertTarget, tlogKeyTarget, ctlogKeyTarget] },
          },
        },
      };

      const subject = new TrustedRootFetcher(tuf as unknown as Updater);

      it('assembles and returns the TrustedRoot', async () => {
        await expect(() => subject.getTrustedRoot()).rejects.toThrow(
          TrustedRootError
        );
      });
    });

    describe('when the TUF target download throws an error', () => {
      // Dummy TUF Updater
      const tuf = {
        refresh: jest.fn(),
        findCachedTarget: jest.fn().mockResolvedValue(undefined),
        downloadTarget: jest.fn().mockRejectedValue(new Error('oops')),
        trustedSet: {
          targets: {
            signed: { targets: [caCertTarget, tlogKeyTarget, ctlogKeyTarget] },
          },
        },
      };

      const subject = new TrustedRootFetcher(tuf as unknown as Updater);

      it('assembles and returns the TrustedRoot', async () => {
        await expect(() => subject.getTrustedRoot()).rejects.toThrow(
          TrustedRootError
        );
      });
    });
  });
});
