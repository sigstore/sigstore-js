import fs from 'fs';
import path from 'path';
import { Updater } from 'tuf-js';
import * as sigstore from '../types/sigstore';
import { TrustedRootFetcher } from './trustroot';

interface RepositoryMap {
  repositories: Record<string, string[]>;
  mapping: {
    paths: string[];
    repositories: string[];
    threshold: number;
    terminating: boolean;
  }[];
}

export async function getTrustedRoot(
  cacheDir: string
): Promise<sigstore.TrustedRoot> {
  initTufCache(cacheDir);
  const repoMap = initRepoMap(cacheDir);

  const repoClients = Object.entries(repoMap.repositories).map(([name, urls]) =>
    initClient(name, urls[0], cacheDir)
  );

  // TODO: Add support for multiple repositories. For now, we just use the first
  // one (the production Sigstore TUF repository).
  const fetcher = new TrustedRootFetcher(repoClients[0]);
  return fetcher.getTrustedRoot();
}

// Initializes the root TUF cache directory
function initTufCache(cacheDir: string): void {
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }
}

// Initializes the repo map (copying it to the cache root dir) and returns the
// content of the repository map.
function initRepoMap(rootDir: string): RepositoryMap {
  const mapDest = path.join(rootDir, 'map.json');

  if (!fs.existsSync(mapDest)) {
    const mapSrc = require.resolve('../../store/map.json');
    fs.copyFileSync(mapSrc, mapDest);
  }

  const buf = fs.readFileSync(mapDest);
  return JSON.parse(buf.toString('utf-8'));
}

function initClient(name: string, url: string, rootDir: string): Updater {
  const repoCachePath = path.join(rootDir, name);
  const targetCachePath = path.join(rootDir, 'targets');
  const tufRootDest = path.join(repoCachePath, 'root.json');

  // Only copy the trusted root if it doesn't already exist. It's possible that
  // the cached root has already been updated, so we don't want to roll it
  // back.
  if (!fs.existsSync(tufRootDest)) {
    const tufRootSrc = require.resolve(`../../store/${name}-root.json`);
    fs.mkdirSync(repoCachePath);
    fs.copyFileSync(tufRootSrc, tufRootDest);
  }

  if (!fs.existsSync(targetCachePath)) {
    fs.mkdirSync(targetCachePath);
  }

  // TODO: Is there some better way to derive the base URL for the targets?
  // Hard-coding for now based on current Sigstore TUF repo layout.
  return new Updater({
    metadataBaseUrl: url,
    targetBaseUrl: `${url}/targets`,
    metadataDir: repoCachePath,
    targetDir: targetCachePath,
  });
}
