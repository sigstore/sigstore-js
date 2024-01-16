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
/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { TrustedRoot } from '@sigstore/protobuf-specs';
import mocktuf, { Target } from '@tufjs/repo-mock';
import fs from 'fs';
import path from 'path';
import { TUFClient } from '../client';
import {
  DEFAULT_MIRROR_URL,
  TUF,
  TUFError,
  TUFOptions,
  getTrustedRoot,
  initTUF,
} from '../index';

describe('public interface', () => {
  it('exports types', () => {
    const tuf: TUF = { getTarget: async () => '' };
    expect(tuf).toBeDefined();

    const options: TUFOptions = {
      cachePath: '',
      mirrorURL: '',
      rootPath: '',
      retry: false,
      timeout: 0,
    };
    expect(options).toBeDefined();
  });

  it('exports errors', () => {
    const err = new TUFError({
      code: 'TUF_READ_TARGET_ERROR',
      message: 'TUF error',
      cause: new Error('cause'),
    });
    expect(err).toBeInstanceOf(Error);
  });

  it('exports funcs', () => {
    expect(getTrustedRoot).toBeInstanceOf(Function);
    expect(initTUF).toBeInstanceOf(Function);
  });

  it('exports constants', () => {
    expect(DEFAULT_MIRROR_URL).toBeDefined();
  });
});

describe('getTrustedRoot', () => {
  let tufRepo: ReturnType<typeof mocktuf> | undefined;
  let options: TUFOptions | undefined;

  const trustedRoot: TrustedRoot = {
    mediaType: 'foo/bar',
    tlogs: [],
    certificateAuthorities: [],
    ctlogs: [],
    timestampAuthorities: [],
  };

  const target: Target = {
    name: 'trusted_root.json',
    content: JSON.stringify(trustedRoot),
  };

  beforeEach(() => {
    tufRepo = mocktuf(target, { metadataPathPrefix: '' });
    options = {
      mirrorURL: tufRepo.baseURL,
      cachePath: tufRepo.cachePath,
      retry: false,
      rootPath: path.join(tufRepo.cachePath, 'root.json'),
    };
  });

  afterEach(() => tufRepo?.teardown());

  it('returns the trusted root', async () => {
    const root = await getTrustedRoot(options);
    expect(root).toBeDefined();
    expect(root).toEqual(trustedRoot);
  });
});

describe('initTUF', () => {
  let tufRepo: ReturnType<typeof mocktuf> | undefined;
  let options: TUFOptions | undefined;

  beforeEach(() => {
    tufRepo = mocktuf([], { metadataPathPrefix: '' });
    options = {
      mirrorURL: tufRepo.baseURL,
      cachePath: tufRepo.cachePath,
      retry: false,
      rootPath: path.join(tufRepo.cachePath, 'root.json'),
    };
  });

  afterEach(() => tufRepo?.teardown());

  it('returns a TUFClient', async () => {
    const tuf = await initTUF(options);
    expect(tuf).toBeInstanceOf(TUFClient);
  });

  it('sets-up the local TUF cache', async () => {
    await initTUF(options);

    const cachePath = path.join(
      tufRepo!.cachePath,
      new URL(options!.mirrorURL!).host
    );
    expect(fs.existsSync(cachePath)).toBe(true);
    expect(fs.existsSync(`${cachePath}/root.json`)).toBe(true);
    expect(fs.existsSync(`${cachePath}/targets`)).toBe(true);
  });
});
