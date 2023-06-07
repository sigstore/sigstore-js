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

import assert from 'assert';
import { generateKeyPairSync } from 'crypto';
import * as jose from 'jose';
import type { Handler, HandlerFn, HandlerFnResult } from '../shared.types';
import type { CA } from './ca';

const CREATE_SIGNING_CERT_PATH = '/api/v2/signingCert';
const DEFAULT_SUBJECT = 'NO-SUBJECT';

interface FulcioHandlerOptions {
  strict?: boolean;
  subjectClaim?: string;
}

export function fulcioHandler(
  ca: CA,
  opts: FulcioHandlerOptions = {}
): Handler {
  return {
    path: CREATE_SIGNING_CERT_PATH,
    fn: createSigningCertHandler(ca, opts),
  };
}

function createSigningCertHandler(
  ca: CA,
  opts: FulcioHandlerOptions
): HandlerFn {
  const strict = opts.strict ?? true;
  const subjectClaim = opts.subjectClaim || 'sub';

  return async (body: string): Promise<HandlerFnResult> => {
    try {
      // Extract relevant fields from the request
      const { subject, publicKey } = strict
        ? parseBody(body, subjectClaim)
        : stubBody();

      // Request certificate from CA
      const cert = await ca.issueCertificate({
        publicKey: fromPEM(publicKey),
        subjectAltName: subject,
      });

      // Format the response
      const response = buildResponse(cert, ca.rootCertificate);

      return { statusCode: 201, response, contentType: 'application/json' };
    } catch (e) {
      assert(e instanceof Error);
      return { statusCode: 400, response: e.message };
    }
  };
}

function parseBody(
  body: string,
  subjectClaim: string
): { subject: string; publicKey: string } {
  const json = JSON.parse(body.toString());
  const oidc = json.credentials.oidcIdentityToken;
  const pem = json.publicKeyRequest.publicKey.content;

  // Decode the JWT
  /* eslint-disable @typescript-eslint/no-explicit-any */
  const claims = jose.decodeJwt(oidc) as any;

  /* istanbul ignore next */
  return { subject: claims[subjectClaim] || DEFAULT_SUBJECT, publicKey: pem };
}

function stubBody(): { subject: string; publicKey: string } {
  const { publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  return {
    subject: DEFAULT_SUBJECT,
    publicKey: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  };
}

function buildResponse(leaf: Buffer, root: Buffer): string {
  const body = {
    signedCertificateEmbeddedSct: {
      chain: {
        certificates: [toPEM(leaf), toPEM(root)],
      },
    },
  };
  return JSON.stringify(body);
}

// PEM string to DER-encoded byte buffer conversion
function fromPEM(pem: string): Buffer {
  return Buffer.from(
    pem.replace(/-{5}(BEGIN|END) .*-{5}/gm, '').replace(/\s/gm, ''),
    'base64'
  );
}

// DER-encoded byte buffer to PEM string conversion
function toPEM(der: Buffer): string {
  return [
    '-----BEGIN CERTIFICATE-----',
    der.toString('base64'),
    '-----END CERTIFICATE-----',
    '',
  ].join('\n');
}
