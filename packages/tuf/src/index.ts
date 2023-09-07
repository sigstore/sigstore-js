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
import { TrustedRoot } from '@sigstore/protobuf-specs';
import { appDataPath } from './appdata';
import {
  TUFOptions as RequiredTUFOptions,
  Retry,
  TUF,
  TUFClient,
} from './client';

export const DEFAULT_MIRROR_URL = 'https://tuf-repo-cdn.sigstore.dev';
const DEFAULT_CACHE_DIR = 'sigstore-js';
const DEFAULT_TUF_ROOT_PATH = '../store/public-good-instance-root.json';
const DEFAULT_RETRY: Retry = { retries: 2 };
const DEFAULT_TIMEOUT = 5000;

const TRUSTED_ROOT_TARGET = 'trusted_root.json';

export type TUFOptions = Partial<RequiredTUFOptions>;

export async function getTrustedRoot(
  /* istanbul ignore next */
  options: TUFOptions = {}
): Promise<TrustedRoot> {
  const client = createClient(options);
  const trustedRoot = await client.getTarget(TRUSTED_ROOT_TARGET);
  return TrustedRoot.fromJSON(JSON.parse(trustedRoot));
}

export async function initTUF(
  /* istanbul ignore next */
  options: TUFOptions = {}
): Promise<TUF> {
  const client = createClient(options);
  return client.refresh().then(() => client);
}

// Create a TUF client with default options
function createClient(options: TUFOptions) {
  /* istanbul ignore next */
  return new TUFClient({
    cachePath: options.cachePath || appDataPath(DEFAULT_CACHE_DIR),
    rootPath: options.rootPath || require.resolve(DEFAULT_TUF_ROOT_PATH),
    mirrorURL: options.mirrorURL || DEFAULT_MIRROR_URL,
    retry: options.retry ?? DEFAULT_RETRY,
    timeout: options.timeout ?? DEFAULT_TIMEOUT,
    force: options.force ?? false,
  });
}

export type { TUF } from './client';
export { TUFError } from './error';
