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
import { encoding as enc } from '../../util';
import {
  Entry,
  ProposedEntry,
  TLog,
  TLogClient,
  TLogClientOptions,
} from './client';
import { toProposedEntry } from './entry';

import type { Affidavit, SignatureBundle, Witness } from '../witness';

export type RekorWitnessOptions = TLogClientOptions;

export class RekorWitness implements Witness {
  private tlog: TLog;

  constructor(options: RekorWitnessOptions) {
    this.tlog = new TLogClient(options);
  }

  public async testify(
    content: SignatureBundle,
    publicKey: string
  ): Promise<Affidavit> {
    const proposedEntry = toProposedEntry(content, publicKey);
    const entry = await this.tlog.createEntry(proposedEntry);
    return affidavit(entry);
  }
}

function affidavit(entry: Entry): Affidavit {
  const set = Buffer.from(
    entry?.verification?.signedEntryTimestamp || '',
    'base64'
  );
  const logID = Buffer.from(entry.logID, 'hex');

  // Parse entry body so we can extract the kind and version.
  const bodyJSON = enc.base64Decode(entry.body);
  const entryBody: ProposedEntry = JSON.parse(bodyJSON);

  const tlogEntry = {
    inclusionPromise: {
      signedEntryTimestamp: set,
    },
    logIndex: entry.logIndex.toString(),
    logId: {
      keyId: logID,
    },
    integratedTime: entry.integratedTime.toString(),
    kindVersion: {
      kind: entryBody.kind,
      version: entryBody.apiVersion,
    },
    inclusionProof: undefined,
    canonicalizedBody: Buffer.from(entry.body, 'base64'),
  };

  return {
    tlogEntries: [tlogEntry],
  };
}
