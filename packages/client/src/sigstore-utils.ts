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
import {
  SerializedBundle,
  SerializedEnvelope,
  bundleToJSON,
  envelopeFromJSON,
  envelopeToJSON,
  toDSSEBundle,
} from '@sigstore/bundle';
import { RekorWitness } from '@sigstore/sign';
import {
  DEFAULT_REKOR_URL,
  DEFAULT_RETRY,
  DEFAULT_TIMEOUT,
  SignOptions,
  createBundleBuilder,
} from './config';
import { SignerFunc } from './types/signature';

export async function createDSSEEnvelope(
  payload: Buffer,
  payloadType: string,
  options: {
    signer: SignerFunc;
  }
): Promise<SerializedEnvelope> {
  const bundler = createBundleBuilder('dsseEnvelope', {
    signer: options.signer,
    tlogUpload: false,
  });
  const bundle = await bundler.create({ data: payload, type: payloadType });
  return envelopeToJSON(bundle.content.dsseEnvelope);
}

// Accepts a signed DSSE envelope and a PEM-encoded public key to be added to the
// transparency log. Returns a Sigstore bundle suitable for offline verification.
export async function createRekorEntry(
  dsseEnvelope: SerializedEnvelope,
  publicKey: string,
  /* istanbul ignore next */
  options: SignOptions = {}
): Promise<SerializedBundle> {
  const envelope = envelopeFromJSON(dsseEnvelope);
  const bundle = toDSSEBundle({
    artifact: envelope.payload,
    artifactType: envelope.payloadType,
    signature: envelope.signatures[0].sig,
    keyHint: envelope.signatures[0].keyid,
  });

  const tlog = new RekorWitness({
    rekorBaseURL:
      options.rekorURL || /* istanbul ignore next */ DEFAULT_REKOR_URL,
    fetchOnConflict: true,
    retry: options.retry ?? DEFAULT_RETRY,
    timeout: options.timeout ?? DEFAULT_TIMEOUT,
  });

  // Add entry to transparency log
  const vm = await tlog.testify(bundle.content, publicKey);

  // Add transparency log entries to bundle
  bundle.verificationMaterial.tlogEntries = [...vm.tlogEntries];

  return bundleToJSON(bundle);
}
