/*
Copyright 2022 The Sigstore Authors.

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
import { Envelope } from '@sigstore/protobuf-specs';
import assert from 'assert';
import { createNotary } from './notary';
import { SignerFunc } from './types/signature';
import * as sigstore from './types/sigstore';
import { RekorWitness } from './witness';

import type { SignOptions } from './config';

export async function createDSSEEnvelope(
  payload: Buffer,
  payloadType: string,
  options: {
    signer: SignerFunc;
  }
): Promise<sigstore.SerializedEnvelope> {
  const notary = createNotary({
    bundleType: 'dsseEnvelope',
    signer: options.signer,
  });

  const bundle = await notary.notarize({ data: payload, type: payloadType });
  assert(bundle.content.$case === 'dsseEnvelope');
  const envelope = bundle.content.dsseEnvelope;

  return Envelope.toJSON(envelope) as sigstore.SerializedEnvelope;
}

// Accepts a signed DSSE envelope and a PEM-encoded public key to be added to the
// transparency log. Returns a Sigstore bundle suitable for offline verification.
export async function createRekorEntry(
  dsseEnvelope: sigstore.SerializedEnvelope,
  publicKey: string,
  options: SignOptions = {}
): Promise<sigstore.SerializedBundle> {
  const envelope = Envelope.fromJSON(dsseEnvelope);
  const tlog = new RekorWitness({
    fetchOnConflict: true,
    rekorBaseURL: options.rekorURL || '',
  });
  const vm = await tlog.testify(
    { $case: 'dsseEnvelope', dsseEnvelope: envelope },
    publicKey
  );

  const bundle: sigstore.Bundle = {
    mediaType: 'application/vnd.redhat.sls.bundle.v1+json',
    content: {
      $case: 'dsseEnvelope',
      dsseEnvelope: envelope,
    },
    verificationMaterial: {
      content: {
        $case: 'publicKey',
        publicKey: {
          hint: dsseEnvelope.signatures[0].keyid,
        },
      },
      timestampVerificationData: vm.timestampVerificationData,
      tlogEntries: vm.tlogEntries,
    },
  };

  return sigstore.bundleToJSON(bundle);
}
