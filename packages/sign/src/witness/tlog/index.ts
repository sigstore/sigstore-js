/*
Copyright 2025 The Sigstore Authors.

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
import { encoding as enc } from '../../util';
import {
  Entry,
  ProposedEntry,
  TLog,
  TLogClient,
  TLogClientOptions,
  TLogV2,
  TLogV2Client,
} from './client';
import { toCreateEntryRequest, toProposedEntry } from './entry';

import type { TransparencyLogEntry } from '@sigstore/bundle';
import type { SignatureBundle, Witness } from '../witness';

export const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';

type TransparencyLogEntries = { tlogEntries: TransparencyLogEntry[] };

export type RekorWitnessOptions = Partial<TLogClientOptions> & {
  entryType?: 'dsse' | 'intoto';
  majorApiVersion?: number;
};

export class RekorWitness implements Witness {
  private tlogV1: TLog;
  private tlogV2: TLogV2;
  private entryType?: 'dsse' | 'intoto';
  private majorApiVersion: number;

  constructor(options: RekorWitnessOptions) {
    this.entryType = options.entryType;
    this.majorApiVersion = options.majorApiVersion || 1;

    this.tlogV1 = new TLogClient({
      ...options,
      rekorBaseURL:
        options.rekorBaseURL || /* istanbul ignore next */ DEFAULT_REKOR_URL,
    });

    this.tlogV2 = new TLogV2Client({
      ...options,
      rekorBaseURL:
        options.rekorBaseURL || /* istanbul ignore next */ DEFAULT_REKOR_URL,
    });
  }

  public async testify(
    content: SignatureBundle,
    publicKey: string
  ): Promise<TransparencyLogEntries> {
    let tlogEntry: TransparencyLogEntry;

    if (this.majorApiVersion === 2) {
      const request = toCreateEntryRequest(content, publicKey);
      tlogEntry = await this.tlogV2.createEntry(request);
    } else {
      const proposedEntry = toProposedEntry(content, publicKey, this.entryType);
      const entry = await this.tlogV1.createEntry(proposedEntry);
      tlogEntry = toTransparencyLogEntry(entry);
    }

    return { tlogEntries: [tlogEntry] };
  }
}

function toTransparencyLogEntry(entry: Entry): TransparencyLogEntry {
  const logID = Buffer.from(entry.logID, 'hex');

  // Parse entry body so we can extract the kind and version.
  const bodyJSON = enc.base64Decode(entry.body);
  const entryBody: ProposedEntry = JSON.parse(bodyJSON);

  const promise = entry?.verification?.signedEntryTimestamp
    ? inclusionPromise(entry.verification.signedEntryTimestamp)
    : undefined;

  const proof = entry?.verification?.inclusionProof
    ? inclusionProof(entry.verification.inclusionProof)
    : undefined;

  const tlogEntry: TransparencyLogEntry = {
    logIndex: entry.logIndex.toString(),
    logId: {
      keyId: logID,
    },
    integratedTime: entry.integratedTime.toString(),
    kindVersion: {
      kind: entryBody.kind,
      version: entryBody.apiVersion,
    },
    inclusionPromise: promise,
    inclusionProof: proof,
    canonicalizedBody: Buffer.from(entry.body, 'base64'),
  };

  return tlogEntry;
}

function inclusionPromise(
  promise: NonNullable<
    NonNullable<Entry['verification']>['signedEntryTimestamp']
  >
): TransparencyLogEntry['inclusionPromise'] {
  return {
    signedEntryTimestamp: Buffer.from(promise, 'base64'),
  };
}

function inclusionProof(
  proof: NonNullable<NonNullable<Entry['verification']>['inclusionProof']>
): TransparencyLogEntry['inclusionProof'] {
  return {
    logIndex: proof.logIndex.toString(),
    treeSize: proof.treeSize.toString(),
    rootHash: Buffer.from(proof.rootHash, 'hex'),
    hashes: proof.hashes.map((h) => Buffer.from(h, 'hex')),
    checkpoint: {
      envelope: proof.checkpoint,
    },
  };
}
