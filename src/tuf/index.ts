import fs from 'fs';
import * as sigstore from '../types/sigstore';

export function getTrustedRoot(): sigstore.TrustedRoot {
  const path = require.resolve('../../store/trusted_root.json');
  const buffer = fs.readFileSync(path);
  const trustedRootJSON = JSON.parse(buffer.toString('utf-8'));
  return sigstore.TrustedRoot.fromJSON(trustedRootJSON);
}
