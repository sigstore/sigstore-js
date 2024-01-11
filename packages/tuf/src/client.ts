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
import path from 'path';
import { Config, Updater } from 'tuf-js';
import { TUFError } from '.';
import { REPO_SEEDS } from './store';
import { readTarget } from './target';

import type { MakeFetchHappenOptions } from 'make-fetch-happen';

export type Retry = MakeFetchHappenOptions['retry'];

const TARGETS_DIR_NAME = 'targets';

type FetchOptions = {
  retry?: Retry;
  timeout?: number;
};

export type TUFOptions = {
  cachePath: string;
  mirrorURL: string;
  rootPath?: string;
  forceCache: boolean;
  forceInit: boolean;
} & FetchOptions;

export interface TUF {
  getTarget(targetName: string): Promise<string>;
}

export class TUFClient implements TUF {
  private updater: Updater;

  constructor(options: TUFOptions) {
    const url = new URL(options.mirrorURL);
    const repoName = encodeURIComponent(
      url.host + url.pathname.replace(/\/$/, '')
    );
    const cachePath = path.join(options.cachePath, repoName);

    initTufCache(cachePath);
    seedCache({
      cachePath,
      mirrorURL: options.mirrorURL,
      tufRootPath: options.rootPath,
      forceInit: options.forceInit,
    });

    this.updater = initClient({
      mirrorURL: options.mirrorURL,
      cachePath,
      forceCache: options.forceCache,
      retry: options.retry,
      timeout: options.timeout,
    });
  }

  public async refresh(): Promise<void> {
    return this.updater.refresh();
  }

  public getTarget(targetName: string): Promise<string> {
    return readTarget(this.updater, targetName);
  }
}

// Initializes the TUF cache directory structure including the initial
// root.json file. If the cache directory does not exist, it will be
// created. If the targets directory does not exist, it will be created.
// If the root.json file does not exist, it will be copied from the
// rootPath argument.
function initTufCache(cachePath: string): void {
  const targetsPath = path.join(cachePath, TARGETS_DIR_NAME);

  if (!fs.existsSync(cachePath)) {
    fs.mkdirSync(cachePath, { recursive: true });
  }

  if (!fs.existsSync(targetsPath)) {
    fs.mkdirSync(targetsPath);
  }
}

// Populates the TUF cache with the initial root.json file. If the root.json
// file does not exist (or we're forcing re-initialization), copy it from either
// the rootPath argument or from one of the repo seeds.
function seedCache({
  cachePath,
  mirrorURL,
  tufRootPath,
  forceInit,
}: {
  cachePath: string;
  mirrorURL: string;
  tufRootPath?: string;
  forceInit: boolean;
}): void {
  const cachedRootPath = path.join(cachePath, 'root.json');

  // If the root.json file does not exist (or we're forcing re-initialization),
  // populate it either from the supplied rootPath or from one of the repo seeds.
  if (!fs.existsSync(cachedRootPath) || forceInit) {
    if (tufRootPath) {
      fs.copyFileSync(tufRootPath, cachedRootPath);
    } else {
      const repoSeed = REPO_SEEDS[mirrorURL];

      if (!repoSeed) {
        throw new TUFError({
          code: 'TUF_INIT_CACHE_ERROR',
          message: `No root.json found for mirror: ${mirrorURL}`,
        });
      }

      fs.writeFileSync(
        cachedRootPath,
        Buffer.from(repoSeed['root.json'], 'base64')
      );

      // Copy any seed targets into the cache
      Object.entries(repoSeed.targets).forEach(([targetName, target]) => {
        fs.writeFileSync(
          path.join(cachePath, TARGETS_DIR_NAME, targetName),
          Buffer.from(target, 'base64')
        );
      });
    }
  }
}

function initClient(
  options: {
    mirrorURL: string;
    cachePath: string;
    forceCache: boolean;
  } & FetchOptions
): Updater {
  const config: Partial<Config> = {
    fetchTimeout: options.timeout,
    fetchRetry: options.retry,
  };

  return new Updater({
    metadataBaseUrl: options.mirrorURL,
    targetBaseUrl: `${options.mirrorURL}/targets`,
    metadataDir: options.cachePath,
    targetDir: path.join(options.cachePath, TARGETS_DIR_NAME),
    forceCache: options.forceCache,
    config,
  });
}
