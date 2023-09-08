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
import { readTarget } from './target';

import type { MakeFetchHappenOptions } from 'make-fetch-happen';

export type Retry = MakeFetchHappenOptions['retry'];

type FetchOptions = {
  retry?: Retry;
  timeout?: number;
};

export type TUFOptions = {
  cachePath: string;
  mirrorURL: string;
  rootPath: string;
  force: boolean;
} & FetchOptions;

export interface TUF {
  getTarget(targetName: string): Promise<string>;
}

interface RemoteConfig {
  mirror: string;
}

export class TUFClient implements TUF {
  private updater: Updater;

  constructor(options: TUFOptions) {
    initTufCache(options);
    const remote = initRemoteConfig(options);
    this.updater = initClient(options.cachePath, remote, options);
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
function initTufCache({
  cachePath,
  rootPath: tufRootPath,
  force,
}: TUFOptions): string {
  const targetsPath = path.join(cachePath, 'targets');
  const cachedRootPath = path.join(cachePath, 'root.json');

  if (!fs.existsSync(cachePath)) {
    fs.mkdirSync(cachePath, { recursive: true });
  }

  if (!fs.existsSync(targetsPath)) {
    fs.mkdirSync(targetsPath);
  }

  // If the root.json file does not exist (or we're forcing re-initialization),
  // copy it from the rootPath argument
  if (!fs.existsSync(cachedRootPath) || force) {
    fs.copyFileSync(tufRootPath, cachedRootPath);
  }

  return cachePath;
}

// Initializes the remote.json file, which contains the URL of the TUF
// repository. If the file does not exist, it will be created. If the file
// exists, it will be parsed and returned.
function initRemoteConfig({
  cachePath,
  mirrorURL,
  force,
}: TUFOptions): RemoteConfig {
  let remoteConfig: RemoteConfig | undefined;
  const remoteConfigPath = path.join(cachePath, 'remote.json');

  // If the remote config file exists, read it and parse it (skip if force is
  // true)
  if (!force && fs.existsSync(remoteConfigPath)) {
    const data = fs.readFileSync(remoteConfigPath, 'utf-8');
    remoteConfig = JSON.parse(data);
  }

  // If the remote config file does not exist (or we're forcing initialization),
  // create it
  if (!remoteConfig || force) {
    remoteConfig = { mirror: mirrorURL };
    fs.writeFileSync(remoteConfigPath, JSON.stringify(remoteConfig));
  }

  return remoteConfig;
}

function initClient(
  cachePath: string,
  remote: RemoteConfig,
  options: FetchOptions
): Updater {
  const baseURL = remote.mirror;
  const config: Partial<Config> = {
    fetchTimeout: options.timeout,
    fetchRetry: options.retry,
  };

  return new Updater({
    metadataBaseUrl: baseURL,
    targetBaseUrl: `${baseURL}/targets`,
    metadataDir: cachePath,
    targetDir: path.join(cachePath, 'targets'),
    config,
  });
}
