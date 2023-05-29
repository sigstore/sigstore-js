import { LogEntry } from '@sigstore/rekor-types';
import canonicalize from 'canonicalize';
import crypto from 'crypto';

type InclusionProof = NonNullable<
  LogEntry['x']['verification']
>['inclusionProof'];

const EMPTY_INCLUSION_PROOF: InclusionProof = {
  checkpoint: '',
  hashes: [],
  logIndex: 0,
  rootHash: '',
  treeSize: 0,
};

export async function initializeTLog(): Promise<TLog> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  return new TLog(publicKey, privateKey);
}

export class TLog {
  public readonly publicKey: crypto.KeyObject;
  private readonly privateKey: crypto.KeyObject;
  public logID: string;

  constructor(publicKey: crypto.KeyObject, privateKey: crypto.KeyObject) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;

    this.logID = crypto
      .createHash('sha256')
      .update(this.publicKey.export({ format: 'der', type: 'spki' }))
      .digest()
      .toString('hex');
  }

  public async log(proposedEntry: object): Promise<LogEntry> {
    const uuid = crypto.randomBytes(32).toString('hex');
    const timestamp = Math.floor(Date.now() / 1000);
    const body = canonicalize(proposedEntry);

    // Random number for logIndex
    const logIndex = Math.floor(Math.random() * 9000000) + 1000000;

    // Calculate SET
    const setData = {
      body: body,
      integratedTime: timestamp,
      logIndex: logIndex,
      logID: this.logID,
    };
    const setBuffer = Buffer.from(canonicalize(setData)!, 'utf8');
    const set = crypto.sign('sha256', setBuffer, this.privateKey);

    return {
      [uuid]: {
        body: Buffer.from(body!).toString('base64'),
        integratedTime: timestamp,
        logID: this.logID,
        logIndex: logIndex,
        verification: {
          inclusionProof: EMPTY_INCLUSION_PROOF,
          signedEntryTimestamp: set.toString('base64'),
        },
      },
    };
  }
}
