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

export interface TLog {
  publicKey: Buffer;
  log(proposedEntry: object): Promise<LogEntry>;
}

export async function initializeTLog(url: string): Promise<TLog> {
  const host = new URL(url).host;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });

  return new TLogImpl(host, publicKey, privateKey);
}

class TLogImpl implements TLog {
  public readonly publicKey: Buffer;
  private readonly privateKey: crypto.KeyObject;
  private readonly host: string;

  constructor(
    host: string,
    publicKey: crypto.KeyObject,
    privateKey: crypto.KeyObject
  ) {
    this.host = host;
    this.privateKey = privateKey;
    this.publicKey = publicKey.export({ format: 'der', type: 'spki' });
  }

  public async log(proposedEntry: object): Promise<LogEntry> {
    const logID = crypto.createHash('sha256').update(this.publicKey).digest();
    const logIndex = crypto.randomInt(10_000_000);
    const timestamp = Math.floor(Date.now() / 1000);
    const body = Buffer.from(canonicalize(proposedEntry)!);

    const entry = { logID, logIndex, timestamp, body };
    const set = this.calculateSET(entry);
    const proof = this.calculateInclusionProof(entry);

    const uuid = crypto.randomBytes(32).toString('hex');

    return {
      [uuid]: {
        body: body,
        integratedTime: timestamp,
        logID: logID.toString('hex'),
        logIndex: logIndex,
        verification: {
          inclusionProof: proof,
          signedEntryTimestamp: set.toString('base64'),
        },
      },
    };
  }

  // Compute the Signed Entry Timestamp (SET) for the given entry.
  // https://github.com/sigstore/rekor/blob/9eb7ec628a41ffed291b605a57e716e86ef0d680/pkg/api/entries.go#L71
  private calculateSET({
    body,
    timestamp,
    logIndex,
    logID,
  }: {
    body: Buffer;
    timestamp: number;
    logIndex: number;
    logID: Buffer;
  }): Buffer {
    const setData = {
      body: body.toString('base64'),
      integratedTime: timestamp,
      logIndex: logIndex,
      logID: logID.toString('hex'),
    };
    const setBuffer = Buffer.from(canonicalize(setData)!, 'utf8');
    return crypto.sign('sha256', setBuffer, this.privateKey);
  }

  // Calculate inclusion proof assuming that the entry being added is the
  // first and only entry in the log.
  // https://github.com/sigstore/rekor/blob/2bd83dacf5a302da83ab4eaf20ff7ad119cb6c11/pkg/util/signed_note.go
  private calculateInclusionProof({
    body,
    timestamp,
    logID,
  }: {
    body: Buffer;
    timestamp: number;
    logID: Buffer;
  }): InclusionProof {
    const treeSize = 1;
    const treeID = crypto.randomInt(2 ** 48 - 1);

    const rootHash = crypto
      .createHash('sha256')
      .update(Buffer.from([0x00]))
      .update(body)
      .digest();

    // Construct checkpoint note
    const note = [
      `${this.host} - ${treeID}`,
      `${treeSize}`,
      rootHash.toString('base64'),
      `Timestamp: ${timestamp * 1_000_000_000}`,
      '',
    ].join('\n');

    // Calculate checkpoint signature
    const sig = crypto.sign('sha256', Buffer.from(note), this.privateKey);
    const hintAndSig = Buffer.concat([logID.subarray(0, 4), sig]);
    const sigLine = `\u2014 ${this.host} ${hintAndSig.toString('base64')}`;

    // Assemble checkpoint from note and signature
    const checkpoint = [note, sigLine, ''].join('\n');

    return {
      logIndex: 0,
      treeSize: treeSize,
      checkpoint,
      hashes: [],
      rootHash: rootHash.toString('hex'),
    };
  }
}
