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
import { TargetFile, Updater } from 'tuf-js';
import { InternalError } from '../error';

// Downloads and returns the specified target from the provided TUF Updater.
export async function readTarget(
  tuf: Updater,
  targetPath: string
): Promise<string> {
  const path = await getTargetPath(tuf, targetPath);

  try {
    return fs.readFileSync(path, 'utf-8');
  } catch (err) {
    throw new InternalError(`error reading trusted root: ${err}`);
  }
}

// Returns the local path to the specified target. If the target is not yet
// cached locally, the provided TUF Updater will be used to download and
// cache the target.
async function getTargetPath(tuf: Updater, target: string): Promise<string> {
  let targetInfo: TargetFile | undefined;
  try {
    targetInfo = await tuf.refresh().then(() => tuf.getTargetInfo(target));
  } catch (err) {
    throw new InternalError(`error refreshing TUF metadata: ${err}`);
  }

  if (!targetInfo) {
    throw new InternalError(`target ${target} not found`);
  }

  let path = await tuf.findCachedTarget(targetInfo);

  // An empty path here means the target has not been cached locally, or is
  // out of date. In either case, we need to download it.
  if (!path) {
    try {
      path = await tuf.downloadTarget(targetInfo);
    } catch (err) {
      throw new InternalError(`error downloading target: ${err}`);
    }
  }

  return path;
}
