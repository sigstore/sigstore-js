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
import mocktuf, { Target } from '@tufjs/repo-mock';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { TUFClient, TUFOptions } from '../client';
import { TUFError } from '../error';

describe('TUFClient', () => {
  describe('constructor', () => {
    const repoSeeds = JSON.parse(
      fs.readFileSync(require.resolve('../../seeds.json')).toString('utf-8')
    );
    let rootSeedDir: string;
    let rootPath: string;

    const repoName = 'example.com';
    const mirrorURL = `https://${repoName}`;
    const cacheRoot = path.join(os.tmpdir(), 'tuf-client-test');
    const cacheDir = path.join(cacheRoot, repoName);
    const forceCache = false;
    const forceInit = false;

    beforeEach(() => {
      rootSeedDir = fs.mkdtempSync(
        path.join(os.tmpdir(), 'tuf-client-test-seed')
      );

      rootPath = path.join(rootSeedDir, 'root-seed.json');
      fs.writeFileSync(
        rootPath,
        Buffer.from(
          repoSeeds['https://tuf-repo-cdn.sigstore.dev']['root.json'],
          'base64'
        )
      );
    });

    afterEach(() => {
      fs.rmSync(cacheRoot, { recursive: true });
      fs.rmSync(rootSeedDir, { recursive: true });
    });

    describe('when the cache directory does not exist', () => {
      it('creates the cache directory', () => {
        new TUFClient({
          cachePath: cacheRoot,
          mirrorURL,
          rootPath,
          forceCache,
          forceInit,
        });
        expect(fs.existsSync(cacheDir)).toEqual(true);
        expect(fs.existsSync(path.join(cacheDir, 'root.json'))).toEqual(true);
      });
    });

    describe('when the cache directory already exists', () => {
      beforeEach(() => {
        fs.mkdirSync(cacheDir, { recursive: true });
        fs.copyFileSync(rootPath, path.join(cacheDir, 'root.json'));
      });

      it('loads config from the existing directory without error', () => {
        expect(
          () =>
            new TUFClient({
              cachePath: cacheDir,
              mirrorURL,
              rootPath,
              forceCache,
              forceInit,
            })
        ).not.toThrow();
      });
    });

    describe('when no explicit root.json is provided', () => {
      describe('when the mirror URL does NOT match one of the embedded roots', () => {
        const mirrorURL = 'https://oops.net';
        it('throws an error', () => {
          expect(
            () =>
              new TUFClient({
                cachePath: cacheDir,
                mirrorURL,
                forceCache,
                forceInit,
              })
          ).toThrowWithCode(TUFError, 'TUF_INIT_CACHE_ERROR');
        });
      });

      describe('when the mirror URL matches one of the embedded roots', () => {
        const mirrorURL = 'https://tuf-repo-cdn.sigstore.dev';
        it('loads the embedded root.json', () => {
          expect(
            () =>
              new TUFClient({
                cachePath: cacheDir,
                mirrorURL,
                forceCache,
                forceInit,
              })
          ).not.toThrow();
        });
      });
    });

    describe('when forcing re-initialization of an existing directory', () => {
      const forceInit = true;

      beforeEach(() => {
        fs.mkdirSync(cacheDir, { recursive: true });
        fs.writeFileSync(path.join(cacheDir, 'root.json'), 'oops');
      });

      it('initializes the client without error', () => {
        expect(
          () =>
            new TUFClient({
              cachePath: cacheRoot,
              mirrorURL,
              rootPath,
              forceCache,
              forceInit,
            })
        ).not.toThrow();
      });

      it('overwrites the existing values', () => {
        new TUFClient({
          cachePath: cacheRoot,
          mirrorURL,
          rootPath,
          forceCache,
          forceInit,
        });

        const root = fs.readFileSync(path.join(cacheDir, 'root.json'), 'utf-8');
        expect(root).toBeDefined();
        expect(root).not.toEqual('oops');
      });
    });
  });

  describe('getTarget', () => {
    let tufRepo: ReturnType<typeof mocktuf> | undefined;
    let options: TUFOptions | undefined;

    const target: Target = {
      name: 'foo',
      content: 'bar',
    };

    beforeEach(() => {
      tufRepo = mocktuf(target, { metadataPathPrefix: '' });
      options = {
        mirrorURL: tufRepo.baseURL,
        cachePath: tufRepo.cachePath,
        retry: false,
        rootPath: path.join(tufRepo.cachePath, 'root.json'),
        forceCache: false,
        forceInit: false,
      };
    });

    afterEach(() => tufRepo?.teardown());

    describe('when the target exists', () => {
      it('returns the target', async () => {
        const subject = new TUFClient(options!);
        const result = await subject.getTarget(target.name);
        expect(result).toEqual(target.content);
      });
    });

    describe('when the target does NOT exist', () => {
      it('throws an error', async () => {
        const subject = new TUFClient(options!);
        await subject.refresh();
        await expect(subject.getTarget('baz')).rejects.toThrowWithCode(
          TUFError,
          'TUF_FIND_TARGET_ERROR'
        );
      });
    });
  });
});
