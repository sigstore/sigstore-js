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
import { SignatureError } from '../error';
import {
  CallbackSigner,
  CallbackSignerOptions,
  KeylessSigner,
  KeylessSignerOptions,
  Signatory,
} from '../signatory';
import {
  RekorWitness,
  RekorWitnessOptions,
  TSAWitness,
  TSAWitnessOptions,
  Witness,
} from '../witness';
import { DSSENotary } from './dsse';
import { MessageNotary } from './message';

import type { Notary, NotaryOptions } from './notary';

export type BundleType = 'messageSignature' | 'dsseEnvelope';

export type NotaryFactoryOptions = {
  bundleType: BundleType;
  tlogUpload?: boolean;
} & Partial<RekorWitnessOptions> &
  Partial<TSAWitnessOptions> &
  Partial<KeylessSignerOptions> &
  Partial<CallbackSignerOptions>;

export function createNotary(options: NotaryFactoryOptions): Notary {
  const notaryOpts: NotaryOptions = {
    signatory: initSignatory(options),
    witnesses: initWitnesses(options),
  };

  switch (options.bundleType) {
    case 'messageSignature':
      return new MessageNotary(notaryOpts);
    case 'dsseEnvelope':
      return new DSSENotary(notaryOpts);
  }
}

function initSignatory(options: NotaryFactoryOptions): Signatory {
  if (isCallbackSignerEnabled(options)) {
    return new CallbackSigner(options);
  } else if (isFulcioEnabled(options)) {
    return new KeylessSigner(options);
  } else {
    throw new SignatureError({
      code: 'NO_SIGNATORY_ERROR',
      message: 'no signatory configured for signing artifacts',
    });
  }
}

function initWitnesses(options: NotaryFactoryOptions): Witness[] {
  const witnesses: Witness[] = [];
  if (isRekorEnabled(options)) {
    witnesses.push(new RekorWitness(options));
  }

  if (isTSAEnabled(options)) {
    witnesses.push(new TSAWitness(options));
  }

  return witnesses;
}

// Type assertion to ensure that the signer is enabled
function isCallbackSignerEnabled(
  options: NotaryFactoryOptions
): options is NotaryFactoryOptions & Required<CallbackSignerOptions> {
  return options.signer !== undefined;
}

// Type assertion to ensure that Fulcio is enabled
function isFulcioEnabled(
  options: NotaryFactoryOptions
): options is NotaryFactoryOptions & Required<KeylessSignerOptions> {
  return (
    options.fulcioBaseURL !== undefined &&
    options.identityProviders !== undefined
  );
}

// Type assertion to ensure that Rekor is enabled
function isRekorEnabled(
  options: NotaryFactoryOptions
): options is NotaryFactoryOptions & Required<RekorWitnessOptions> {
  return options.rekorBaseURL !== undefined && (options.tlogUpload ?? true);
}

// Type assertion to ensure that TSA is enabled
function isTSAEnabled(
  options: NotaryFactoryOptions
): options is NotaryFactoryOptions & Required<TSAWitnessOptions> {
  return options.tsaBaseURL !== undefined;
}
