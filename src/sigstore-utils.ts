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
import { TLog, TLogClient } from './tlog';
import {
  bundleToJSON,
  envelopeFromJSON,
  envelopeToJSON,
  Envelope as DSSEEnvelope,
} from './types/bundle';
import { extractSignatureMaterial, SignerFunc } from './types/signature';
import { dsse } from './util';
import {
  Bundle,
  Envelope,
  SignOptions,
  DEFAULT_REKOR_BASE_URL,
} from './sigstore';

function createTLogClient(options: { rekorBaseURL?: string }): TLog {
  return new TLogClient({
    rekorBaseURL: options.rekorBaseURL || DEFAULT_REKOR_BASE_URL,
  });
}

export async function createDSSEEnvelope(
  payload: Buffer,
  payloadType: string,
  options: {
    signer: SignerFunc;
  }
): Promise<Envelope> {
  // Pre-authentication encoding to be signed
  const paeBuffer = dsse.preAuthEncoding(payloadType, payload);

  // Get signature and verification material for pae
  const sigMaterial = await options.signer(paeBuffer);

  const envelope: DSSEEnvelope = {
    payloadType,
    payload,
    signatures: [
      {
        keyid: sigMaterial.key?.id || '',
        sig: sigMaterial.signature,
      },
    ],
  };

  return envelopeToJSON(envelope) as Envelope;
}

// Accepts a signed DSSE envelope and a PEM-encoded public key to be added to the
// transparency log. Returns a Sigstore bundle suitable for offline verification.
export async function createRekorEntry(
  dsseEnvelope: Envelope,
  publicKey: string,
  options: SignOptions = {}
): Promise<Bundle> {
  const envelope = envelopeFromJSON(dsseEnvelope);
  const tlog = createTLogClient(options);

  const sigMaterial = extractSignatureMaterial(envelope, publicKey);
  const bundle = await tlog.createDSSEEntry(envelope, sigMaterial);
  return bundleToJSON(bundle) as Bundle;
}
