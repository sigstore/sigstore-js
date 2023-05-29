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
import { fromPartial } from '@total-typescript/shoehorn';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { TargetFile, Updater } from 'tuf-js';
import { TUFError } from '../error';
import { readTarget } from '../target';

describe('readTarget', () => {
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

  describe('when the target is already cached', () => {
    const tuf: Updater = fromPartial({
      refresh: jest.fn().mockResolvedValue(undefined),
      getTargetInfo: jest.fn().mockResolvedValue(targetFile),
      findCachedTarget: jest.fn().mockReturnValue(targetFilePath),
    });

    it('returns the target', async () => {
      const target = await readTarget(tuf, targetPath);
      expect(target).toEqual(targetContent);
    });
  });

  describe('when the target is not cached locally', () => {
    describe('when the target download is successful', () => {
      const tuf: Updater = fromPartial({
        refresh: jest.fn().mockResolvedValue(undefined),
        getTargetInfo: jest.fn().mockResolvedValue(targetFile),
        findCachedTarget: jest.fn().mockReturnValue(undefined),
        downloadTarget: jest.fn().mockReturnValue(targetFilePath),
      });

      it('downloads and returns the target', async () => {
        const target = await readTarget(tuf, targetPath);
        expect(target).toEqual(targetContent);
      });
    });

    describe('when the target download fails', () => {
      const tuf: Updater = fromPartial({
        refresh: jest.fn().mockResolvedValue(undefined),
        getTargetInfo: jest.fn().mockResolvedValue(targetFile),
        findCachedTarget: jest.fn().mockReturnValue(undefined),
        downloadTarget: jest.fn().mockRejectedValue(new Error('oops')),
      });

      it('throw an error', async () => {
        await expect(readTarget(tuf, targetPath)).rejects.toThrowError(
          TUFError
        );
      });

      it('throws an error with code TUF_DOWNLOAD_TARGET_ERROR', async () => {
        expect.assertions(1);
        await readTarget(tuf, targetPath).catch((err) => {
          expect(err.code).toEqual('TUF_DOWNLOAD_TARGET_ERROR');
        });
      });
    });
  });

  describe('when the TUF refresh throws an error', () => {
    const tuf: Updater = fromPartial({
      refresh: jest.fn().mockRejectedValue(new Error('oops')),
    });

    it('throws an error', async () => {
      await expect(readTarget(tuf, targetPath)).rejects.toThrow(TUFError);
    });

    it('throws an error with code TUF_REFRESH_METADATA_ERROR', async () => {
      expect.assertions(1);
      await readTarget(tuf, targetPath).catch((err) => {
        expect(err.code).toEqual('TUF_REFRESH_METADATA_ERROR');
      });
    });
  });

  describe('when the target cannot be found', () => {
    const tuf: Updater = fromPartial({
      refresh: jest.fn().mockResolvedValue(undefined),
      getTargetInfo: jest.fn().mockResolvedValue(undefined),
    });

    it('throws an error', async () => {
      await expect(readTarget(tuf, targetPath)).rejects.toThrow(TUFError);
    });

    it('throws an error with code TUF_FIND_TARGET_ERROR', async () => {
      expect.assertions(1);
      await readTarget(tuf, targetPath).catch((err) => {
        expect(err.code).toEqual('TUF_FIND_TARGET_ERROR');
      });
    });
  });

  describe('when the cache read fails', () => {
    const tuf: Updater = fromPartial({
      refresh: jest.fn().mockResolvedValue(undefined),
      getTargetInfo: jest.fn().mockResolvedValue(targetFile),
      findCachedTarget: jest.fn().mockReturnValue('invalidpath'),
    });

    it('throws an error', async () => {
      await expect(readTarget(tuf, targetPath)).rejects.toThrow(TUFError);
    });

    it('throws an error with code TUF_READ_TARGET_ERROR', async () => {
      expect.assertions(1);
      await readTarget(tuf, targetPath).catch((err) => {
        expect(err.code).toEqual('TUF_READ_TARGET_ERROR');
      });
    });
  });
});
