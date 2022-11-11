import crypto from 'crypto';
import dsse from './dsse';
import signature from './signature';

export default { dsse, signature };

const tlogKey = crypto.createPublicKey(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`);

const tlogKeyID = crypto
  .createHash('sha256')
  .update(tlogKey.export({ format: 'der', type: 'spki' }))
  .digest()
  .toString('hex');

export const tlogKeys = { [tlogKeyID]: tlogKey };
