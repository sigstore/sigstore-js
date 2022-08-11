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
import { KeyLike } from 'crypto';
import * as sigstore from './sigstore';

export interface Signature {
  keyid: string;
  sig: string;
}

export interface Envelope {
  payloadType: string;
  payload: string;
  signatures: Signature[];
}

export async function sign(
  payload: Buffer,
  payloadType: string,
  options: sigstore.SignOptions = {}
): Promise<Envelope> {
  const paeBuffer = pae(payloadType, payload);
  const signedPayload = await sigstore.sign(paeBuffer, options);

  const envelope: Envelope = {
    payloadType: payloadType,
    payload: payload.toString('base64'),
    signatures: [
      {
        keyid: '',
        sig: signedPayload.base64Signature,
      },
    ],
  };

  return envelope;
}

export async function verify(
  envelope: Envelope,
  certificate: KeyLike,
  options: sigstore.VerifierOptions = {}
): Promise<boolean> {
  const payloadType = envelope.payloadType;
  const payload = Buffer.from(envelope.payload, 'base64');
  const signature = envelope.signatures[0].sig;

  const paeBuffer = pae(payloadType, payload);
  const verified = await sigstore.verify(
    paeBuffer,
    signature,
    certificate,
    options
  );

  return verified;
}

// DSSE Pre-Authentication Encoding
function pae(payloadType: string, payload: Buffer): Buffer {
  const prefix = Buffer.from(
    `DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `,
    'ascii'
  );
  return Buffer.concat([prefix, payload]);
}
