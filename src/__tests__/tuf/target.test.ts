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
import { TargetFile, Updater } from 'tuf-js';
import { InternalError } from '../../error';
import { getTarget } from '../../tuf/target';

describe('TrustedRootFetcher', () => {
  const targetContent = 'sample trusted root content';
  const targetPath = 'truststed_root.json';

  const targetFile = new TargetFile({
    path: targetPath,
    length: targetContent.length,
    hashes: { sha256: 'DEADBEEF' },
  });

  // Set-up a directory to use as our TUF cache and write a target to it
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tuf-cache-test-'));
  const targetFilePath = path.join(tempDir, targetPath);
  fs.writeFileSync(targetFilePath, targetContent);

  afterAll(() => {
    fs.rmSync(tempDir, { recursive: true });
  });

  describe('getTrustedRoot', () => {
    describe('when the target is already cached', () => {
      const tuf = {
        refresh: jest.fn().mockResolvedValue(undefined),
        getTargetInfo: jest.fn().mockResolvedValue(targetFile),
        findCachedTarget: jest.fn().mockReturnValue(targetFilePath),
      } as unknown as Updater;

      it('returns the target', async () => {
        const target = await getTarget(tuf, targetPath);
        expect(target).toEqual(targetContent);
      });
    });

    describe('when the target is not cached locally', () => {
      describe('when the target download is successful', () => {
        const tuf = {
          refresh: jest.fn().mockResolvedValue(undefined),
          getTargetInfo: jest.fn().mockResolvedValue(targetFile),
          findCachedTarget: jest.fn().mockReturnValue(undefined),
          downloadTarget: jest.fn().mockReturnValue(targetFilePath),
        } as unknown as Updater;

        it('downloads and returns the target', async () => {
          const target = await getTarget(tuf, targetPath);
          expect(target).toEqual(targetContent);
        });
      });

      describe('when the target download fails', () => {
        const tuf = {
          refresh: jest.fn().mockResolvedValue(undefined),
          getTargetInfo: jest.fn().mockResolvedValue(targetFile),
          findCachedTarget: jest.fn().mockReturnValue(undefined),
          downloadTarget: jest.fn().mockRejectedValue(new Error('oops')),
        } as unknown as Updater;

        it('throw an error', async () => {
          await expect(() => getTarget(tuf, targetPath)).rejects.toThrow(
            InternalError
          );
        });
      });
    });

    describe('when the TUF refresh throws an error', () => {
      const tuf = {
        refresh: jest.fn().mockRejectedValue(new Error('oops')),
      } as unknown as Updater;

      it('throws an error', async () => {
        await expect(() => getTarget(tuf, targetPath)).rejects.toThrow(
          InternalError
        );
      });
    });

    describe('when the target cannot be found', () => {
      const tuf = {
        refresh: jest.fn().mockResolvedValue(undefined),
        getTargetInfo: jest.fn().mockResolvedValue(undefined),
      } as unknown as Updater;

      it('throws an error', async () => {
        await expect(() => getTarget(tuf, targetPath)).rejects.toThrow(
          InternalError
        );
      });
    });
  });

  describe('when the cache read fails', () => {
    const tuf = {
      refresh: jest.fn().mockResolvedValue(undefined),
      getTargetInfo: jest.fn().mockResolvedValue(targetFile),
      findCachedTarget: jest.fn().mockReturnValue('invalidpath'),
    } as unknown as Updater;

    it('throws an error', async () => {
      await expect(() => getTarget(tuf, targetPath)).rejects.toThrow(
        InternalError
      );
    });
  });
});
