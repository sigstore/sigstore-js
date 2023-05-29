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

export interface TLog {
  publicKey: Buffer;
  log(proposedEntry: object): Promise<LogEntry>;
}

export async function initializeTLog(): Promise<TLog> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  return new TLogImpl(publicKey, privateKey);
}

class TLogImpl implements TLog {
  public readonly publicKey: Buffer;
  private readonly privateKey: crypto.KeyObject;

  constructor(publicKey: crypto.KeyObject, privateKey: crypto.KeyObject) {
    this.privateKey = privateKey;
    this.publicKey = publicKey.export({ format: 'der', type: 'spki' });
  }

  public async log(proposedEntry: object): Promise<LogEntry> {
    const uuid = crypto.randomBytes(32).toString('hex');
    const timestamp = Math.floor(Date.now() / 1000);
    const logID = crypto
      .createHash('sha256')
      .update(this.publicKey)
      .digest()
      .toString('hex');
    const body = canonicalize(proposedEntry);

    // Random number for logIndex
    const logIndex = Math.floor(Math.random() * 9000000) + 1000000;

    // Calculate SET
    // https://github.com/sigstore/rekor/blob/9eb7ec628a41ffed291b605a57e716e86ef0d680/pkg/api/entries.go#L71
    const setData = {
      body: body,
      integratedTime: timestamp,
      logIndex: logIndex,
      logID: logID,
    };
    const setBuffer = Buffer.from(canonicalize(setData)!, 'utf8');
    const set = crypto.sign('sha256', setBuffer, this.privateKey);

    return {
      [uuid]: {
        body: Buffer.from(body!).toString('base64'),
        integratedTime: timestamp,
        logID: logID,
        logIndex: logIndex,
        verification: {
          inclusionProof: EMPTY_INCLUSION_PROOF,
          signedEntryTimestamp: set.toString('base64'),
        },
      },
    };
  }
}
