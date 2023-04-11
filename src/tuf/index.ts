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
import { Updater } from 'tuf-js';
import * as sigstore from '../types/sigstore';
import { appdata } from '../util';
import { readTarget } from './target';

const TRUSTED_ROOT_TARGET = 'trusted_root.json';

const DEFAULT_CACHE_DIR = appdata.appDataPath('sigstore-js');
const DEFAULT_MIRROR_URL = 'https://tuf-repo-cdn.sigstore.dev';
const DEFAULT_TUF_ROOT_PATH = '../../store/public-good-instance-root.json';

export interface TUFOptions {
  cachePath?: string;
  mirrorURL?: string;
  rootPath?: string;
}

interface RemoteConfig {
  mirror: string;
}

export async function getTrustedRoot(
  options: TUFOptions = {}
): Promise<sigstore.TrustedRoot> {
  const trustedRoot = await getTarget(TRUSTED_ROOT_TARGET, options);
  return sigstore.TrustedRoot.fromJSON(JSON.parse(trustedRoot));
}

export async function getTarget(
  targetName: string,
  options: TUFOptions = {}
): Promise<string> {
  const cachePath = options.cachePath || DEFAULT_CACHE_DIR;
  const tufRootPath =
    options.rootPath || require.resolve(DEFAULT_TUF_ROOT_PATH);
  const mirrorURL = options.mirrorURL || DEFAULT_MIRROR_URL;

  initTufCache(cachePath, tufRootPath);
  const remote = initRemoteConfig(cachePath, mirrorURL);
  const repoClient = initClient(cachePath, remote);

  return readTarget(repoClient, targetName);
}

// Initializes the TUF cache directory structure including the initial
// root.json file. If the cache directory does not exist, it will be
// created. If the targets directory does not exist, it will be created.
// If the root.json file does not exist, it will be copied from the
// rootPath argument.
function initTufCache(cachePath: string, tufRootPath: string): string {
  const targetsPath = path.join(cachePath, 'targets');
  const cachedRootPath = path.join(cachePath, 'root.json');

  if (!fs.existsSync(cachePath)) {
    fs.mkdirSync(cachePath, { recursive: true });
  }

  if (!fs.existsSync(targetsPath)) {
    fs.mkdirSync(targetsPath);
  }

  if (!fs.existsSync(cachedRootPath)) {
    fs.copyFileSync(tufRootPath, cachedRootPath);
  }

  return cachePath;
}

// Initializes the remote.json file, which contains the URL of the TUF
// repository. If the file does not exist, it will be created. If the file
// exists, it will be parsed and returned.
function initRemoteConfig(rootDir: string, mirrorURL: string): RemoteConfig {
  let remoteConfig: RemoteConfig | undefined;
  const remoteConfigPath = path.join(rootDir, 'remote.json');

  if (fs.existsSync(remoteConfigPath)) {
    const data = fs.readFileSync(remoteConfigPath, 'utf-8');
    remoteConfig = JSON.parse(data);
  }

  if (!remoteConfig) {
    remoteConfig = { mirror: mirrorURL };
    fs.writeFileSync(remoteConfigPath, JSON.stringify(remoteConfig));
  }

  return remoteConfig;
}

function initClient(cachePath: string, remote: RemoteConfig): Updater {
  const baseURL = remote.mirror;

  return new Updater({
    metadataBaseUrl: baseURL,
    targetBaseUrl: `${baseURL}/targets`,
    metadataDir: cachePath,
    targetDir: path.join(cachePath, 'targets'),
  });
}
