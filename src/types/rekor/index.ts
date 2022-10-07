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
import { crypto, encoding as enc, json, pem } from '../../util';
import { Bundle, Envelope } from '../bundle';
import { SignatureMaterial } from '../signature';
import { HashedRekorV001Schema } from './__generated__/hashedrekord';
import { IntotoV001Schema, IntotoV002Schema } from './__generated__/intoto';

const INTOTO_KIND = 'intoto';
const HASHEDREKORD_KIND = 'hashedrekord';

export type HashedRekordKind = {
  apiVersion: '0.0.1';
  kind: typeof HASHEDREKORD_KIND;
  spec: HashedRekorV001Schema;
};

export type IntotoKind =
  | {
      apiVersion: '0.0.1';
      kind: typeof INTOTO_KIND;
      spec: IntotoV001Schema;
    }
  | {
      apiVersion: '0.0.2';
      kind: typeof INTOTO_KIND;
      spec: IntotoV002Schema;
    };

export type EntryKind = HashedRekordKind | IntotoKind;

export interface Entry {
  uuid: string;
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  verification: EntryVerification;
  attestation?: object;
}

export interface EntryVerification {
  inclusionProof: InclusionProof;
  signedEntryTimestamp: string;
}

export interface InclusionProof {
  hashes: string[];
  logIndex: number;
  rootHash: string;
  treeSize: number;
}

export interface VerificationPayload {
  body: any;
  integratedTime: number;
  logIndex: number;
  logID: string;
}

export const rekor = {
  toProposedIntotoEntry: (
    envelope: Envelope,
    signature: SignatureMaterial
  ): IntotoKind => {
    // Double-encode payload and signature cause that's what Rekor expects
    const payload = enc.base64Encode(envelope.payload.toString('base64'));
    const sig = enc.base64Encode(envelope.signatures[0].sig.toString('base64'));
    const keyid = signature.key?.id || '';
    const publicKey = enc.base64Encode(toPublicKey(signature));
    const hash = crypto.hash(JSON.stringify(envelope.payload)).toString('hex');

    return {
      apiVersion: '0.0.2',
      kind: 'intoto',
      spec: {
        content: {
          envelope: {
            payloadType: envelope.payloadType,
            payload: payload,
            signatures: [{ sig, keyid, publicKey }],
          },
          hash: { algorithm: 'sha256', value: hash },
        },
      },
    };
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

  toVerificationPayload: (bundle: Bundle): VerificationPayload => {
    // Ensure bundle as tlog entries
    const entries = bundle.verificationData?.tlogEntries;
    if (!entries || entries.length == 0) {
      throw new Error('No tlog entries found in bundle');
    }

    const { integratedTime, logIndex, logId } = entries[0];

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
          certificates: [cert],
          signature: sig,
          key: undefined,
        };
        body = rekor.toProposedHashedRekordEntry(digest, sigMaterial);
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
