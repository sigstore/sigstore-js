import { TrustedRoot } from '@sigstore/protobuf-specs';
import * as tuf from '@sigstore/tuf';
import { toTrustMaterial, TrustMaterial } from '@sigstore/verify';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { TUF_STAGING_ROOT, TUF_STAGING_URL } from './staging';

// Initialize TrustMaterial from TUF
export async function trustMaterialFromTUF(
  staging: boolean
): Promise<TrustMaterial> {
  const opts: tuf.TUFOptions = {};

  if (staging) {
    // Write the initial root.json to a temporary directory
    const tmpPath = await fs.mkdtemp(path.join(os.tmpdir(), 'sigstore-'));
    const rootPath = path.join(tmpPath, 'root.json');
    await fs.writeFile(rootPath, Buffer.from(TUF_STAGING_ROOT, 'base64'));

    opts.mirrorURL = TUF_STAGING_URL;
    opts.rootPath = rootPath;
  }

  const trustedRoot = await tuf.getTrustedRoot(opts);
  return toTrustMaterial(trustedRoot);
}

// Initialize TrustMaterial from a file
export async function trustMaterialFromPath(
  path: string
): Promise<TrustMaterial> {
  const trustedRoot = await fs
    .readFile(path)
    .then((data) => JSON.parse(data.toString()));
  return toTrustMaterial(TrustedRoot.fromJSON(trustedRoot));
}
