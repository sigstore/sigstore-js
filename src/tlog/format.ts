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
import { Bundle, Envelope } from '../types/bundle';
import { SignatureMaterial } from '../types/signature';
import { crypto, encoding as enc, json, pem } from '../util';
import {
  HashedRekordKind,
  IntotoKind,
  INTOTO_KIND,
  VerificationPayload,
} from './types';

export const rekor = {
  toProposedIntotoEntry: (
    envelope: Envelope,
    signature: SignatureMaterial,
    apiVersion = '0.0.2'
  ): IntotoKind => {
    // Double-encode payload and signature cause that's what Rekor expects
    const payload = enc.base64Encode(envelope.payload.toString('base64'));
    const sig = enc.base64Encode(envelope.signatures[0].sig.toString('base64'));
    const keyid = envelope.signatures[0].keyid;
    const publicKey = enc.base64Encode(toPublicKey(signature));
    const payloadHash = crypto.hash(envelope.payload).toString('hex');

    // Create the envelop portion first so that we can calculate its hash
    const dsse: IntotoKind['spec']['content']['envelope'] = {
      payloadType: envelope.payloadType,
      payload: payload,
      signatures: [{ sig, publicKey }],
    };

    // If the keyid is an empty string, Rekor seems to remove it altogether. We
    // need to do the same here so that we can properly recreate the entry for
    // verification.
    if (keyid.length > 0) {
      dsse.signatures[0].keyid = keyid;
    }

    const envelopeHash = crypto.hash(json.canonicalize(dsse)).toString('hex');

    switch (apiVersion) {
      case '0.0.2':
        return {
          apiVersion: apiVersion,
          kind: INTOTO_KIND,
          spec: {
            content: {
              envelope: dsse,
              hash: { algorithm: 'sha256', value: envelopeHash },
              payloadHash: { algorithm: 'sha256', value: payloadHash },
            },
          },
        };
      default:
        throw new Error(`Unsupported API version: ${apiVersion}`);
    }
  },

  toProposedHashedRekordEntry: (
    digest: Buffer,
    signature: SignatureMaterial
  ): HashedRekordKind => {
    const hexDigest = digest.toString('hex');
    const b64Signature = signature.signature.toString('base64');
    const b64Key = enc.base64Encode(toPublicKey(signature));

    return {
      apiVersion: '0.0.1',
      kind: 'hashedrekord',
      spec: {
        data: {
          hash: {
            algorithm: 'sha256',
            value: hexDigest,
          },
        },
        signature: {
          content: b64Signature,
          publicKey: {
            content: b64Key,
          },
        },
      },
    };
  },

  toVerificationPayload: (bundle: Bundle, index = 0): VerificationPayload => {
    // Ensure bundle has tlog entries
    const entries = bundle.verificationData?.tlogEntries;
    if (!entries || entries.length - 1 < index) {
      throw new Error('No tlog entries found in bundle');
    }

    const { integratedTime, logIndex, logId } = entries[index];

    if (!logId) {
      throw new Error('No logId found in bundle');
    }

    let cert = '';
    // Ensure there is a certificate
    switch (bundle.verificationMaterial?.content?.$case) {
      case 'x509CertificateChain': {
        const der =
          bundle.verificationMaterial.content.x509CertificateChain
            .certificates[0];
        cert = pem.fromDER(der.derBytes);
        break;
      }
      default:
        throw new Error('No certificate found in bundle');
    }

    let body = undefined;
    switch (bundle.content?.$case) {
      case 'messageSignature': {
        const digest =
          bundle.content.messageSignature.messageDigest?.digest ||
          Buffer.from('');
        const sig = bundle.content.messageSignature.signature;
        const sigMaterial: SignatureMaterial = {
          signature: sig,
          certificates: [cert],
          key: undefined,
        };
        body = rekor.toProposedHashedRekordEntry(digest, sigMaterial);
        break;
      }
      case 'dsseEnvelope': {
        const envelope = bundle.content.dsseEnvelope;
        const sig = bundle.content.dsseEnvelope.signatures[0].sig;
        body = rekor.toProposedIntotoEntry(envelope, {
          signature: sig,
          certificates: [cert],
          key: undefined,
        });

        // When Rekor saves the entry it removes the payload from the envelope
        if (body.apiVersion === '0.0.2') {
          delete body.spec.content?.envelope?.payload;
        }
        break;
      }
      default:
        throw new Error('Unsupported bundle type');
    }

    if (!logId) {
      throw new Error('No log ID found in bundle');
    }

    return {
      body: enc.base64Encode(json.canonicalize(body)),
      integratedTime: Number(integratedTime),
      logIndex: Number(logIndex),
      logID: logId.keyId.toString('hex'),
    };
  },
};

function toPublicKey(signature: SignatureMaterial): string {
  return signature.certificates
    ? signature.certificates[0]
    : signature.key.value;
}
