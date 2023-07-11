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
} from '@sigstore/bundle';
import { SignOptions, createTLogClient } from './config';
import { SignerFunc, extractSignatureMaterial } from './types/signature';
import * as sigstore from './types/sigstore';
import { dsse } from './util';

export async function createDSSEEnvelope(
  payload: Buffer,
  payloadType: string,
  options: {
    signer: SignerFunc;
  }
): Promise<SerializedEnvelope> {
  // Pre-authentication encoding to be signed
  const paeBuffer = dsse.preAuthEncoding(payloadType, payload);

  // Get signature and verification material for pae
  const sigMaterial = await options.signer(paeBuffer);

  const envelope: sigstore.Envelope = {
    payloadType,
    payload,
    signatures: [
      {
        keyid: sigMaterial.key?.id || '',
        sig: sigMaterial.signature,
      },
    ],
  };

  return sigstore.Envelope.toJSON(envelope) as SerializedEnvelope;
}

// Accepts a signed DSSE envelope and a PEM-encoded public key to be added to the
// transparency log. Returns a Sigstore bundle suitable for offline verification.
export async function createRekorEntry(
  dsseEnvelope: SerializedEnvelope,
  publicKey: string,
  options: SignOptions = {}
): Promise<SerializedBundle> {
  const envelope = sigstore.Envelope.fromJSON(dsseEnvelope);
  const tlog = createTLogClient(options);

  const sigMaterial = extractSignatureMaterial(envelope, publicKey);
  const entry = await tlog.createDSSEEntry(envelope, sigMaterial, {
    fetchOnConflict: true,
  });

  const bundle = sigstore.toDSSEBundle({
    envelope,
    signature: sigMaterial,
    tlogEntry: entry,
  });
  return bundleToJSON(bundle);
}
