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
import { TrustedRootFetcher } from './trustroot';

const DEFAULT_MIRROR_URL = 'https://sigstore-tuf-root.storage.googleapis.com';
const DEFAULT_ROOT_PATH = '../../store/public-good-instance-root.json';

export interface TUFOptions {
  mirrorURL?: string;
  rootPath?: string;
}

interface RemoteConfig {
  mirror: string;
}

export async function getTrustedRoot(
  cachePath: string,
  options: TUFOptions = {}
): Promise<sigstore.TrustedRoot> {
  initTufCache(cachePath, options.rootPath);
  const mirror = initRemoteConfig(cachePath, options.mirrorURL);
  const repoClient = initClient(cachePath, mirror);

  const fetcher = new TrustedRootFetcher(repoClient);
  return fetcher.getTrustedRoot();
}

// Initializes the TUF cache directory structure
function initTufCache(cachePath: string, rootPath: string | undefined): string {
  const targetsPath = path.join(cachePath, 'targets');
  const cachedRootPath = path.join(cachePath, 'root.json');

  if (!fs.existsSync(cachePath)) {
    fs.mkdirSync(cachePath, { recursive: true });
  }

  if (!fs.existsSync(targetsPath)) {
    fs.mkdirSync(targetsPath);
  }

  if (!fs.existsSync(cachedRootPath)) {
    const initialRootPath = rootPath || require.resolve(DEFAULT_ROOT_PATH);
    fs.copyFileSync(initialRootPath, cachedRootPath);
  }

  return cachePath;
}

// Initializes the remote.json file, which contains the URL of the TUF
// repository. If the file does not exist, it will be created with the
// default URL. If the file exists, it will be parsed and returned.
function initRemoteConfig(
  rootDir: string,
  mirrorURL: string | undefined
): RemoteConfig {
  let remoteConfig: RemoteConfig | undefined;
  const remoteConfigpath = path.join(rootDir, 'remote.json');

  if (fs.existsSync(remoteConfigpath)) {
    const buf = fs.readFileSync(remoteConfigpath);
    remoteConfig = JSON.parse(buf.toString('utf-8'));
  }

  if (!remoteConfig) {
    remoteConfig = { mirror: mirrorURL || DEFAULT_MIRROR_URL };
    fs.writeFileSync(remoteConfigpath, JSON.stringify(remoteConfig));
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
