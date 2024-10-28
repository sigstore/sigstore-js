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
import type { CA, ExtensionValue } from './ca';
import x509 from '@peculiar/x509';

const CREATE_SIGNING_CERT_PATH = '/api/v2/signingCert';
const DEFAULT_SUBJECT = 'NO-SUBJECT';
const DEFAULT_ISSUER = 'https://fake.oidcissuer.com';

const ISSUER_EXT_OID_V1 = '1.3.6.1.4.1.57264.1.1';
const ISSUER_EXT_OID_V2 = '1.3.6.1.4.1.57264.1.8';

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
      const { subject, issuer, publicKey, claims } = strict
        ? parseBody(body, subjectClaim)
        : stubBody();

      const extensions: ExtensionValue[] = [
        { oid: ISSUER_EXT_OID_V1, value: issuer, legacy: true },
        { oid: ISSUER_EXT_OID_V2, value: issuer },
      ];

      switch (issuer) {
        case 'https://token.actions.githubusercontent.com': {
          const server_url = 'https://github.com/';
          extensions.push(
            {
              oid: '1.3.6.1.4.1.57264.1.2',
              value: claims['event_name'],
              legacy: true,
            },
            {
              oid: '1.3.6.1.4.1.57264.1.3',
              value: claims['sha'],
              legacy: true,
            },
            {
              oid: '1.3.6.1.4.1.57264.1.4',
              value: claims['workflow'],
              legacy: true,
            },
            {
              oid: '1.3.6.1.4.1.57264.1.5',
              value: claims['repository'],
              legacy: true,
            },
            {
              oid: '1.3.6.1.4.1.57264.1.6',
              value: claims['ref'],
              legacy: true,
            },
            {
              oid: '1.3.6.1.4.1.57264.1.9',
              value: server_url + claims['job_workflow_ref'],
            },
            {
              oid: '1.3.6.1.4.1.57264.1.10',
              value: claims['job_workflow_sha'],
            },
            {
              oid: '1.3.6.1.4.1.57264.1.11',
              value: claims['runner_environment'],
            },
            {
              oid: '1.3.6.1.4.1.57264.1.12',
              value: server_url + claims['repository'],
            },
            { oid: '1.3.6.1.4.1.57264.1.13', value: claims['sha'] },
            { oid: '1.3.6.1.4.1.57264.1.14', value: claims['ref'] },
            { oid: '1.3.6.1.4.1.57264.1.15', value: claims['repository_id'] },
            {
              oid: '1.3.6.1.4.1.57264.1.16',
              value: server_url + claims['repository_owner'],
            },
            {
              oid: '1.3.6.1.4.1.57264.1.17',
              value: claims['repository_owner_id'],
            },
            {
              oid: '1.3.6.1.4.1.57264.1.18',
              value: server_url + claims['workflow_ref'],
            },
            { oid: '1.3.6.1.4.1.57264.1.19', value: claims['workflow_sha'] },
            { oid: '1.3.6.1.4.1.57264.1.20', value: claims['event_name'] },
            {
              oid: '1.3.6.1.4.1.57264.1.21',
              value: `${server_url}${claims.repository}/actions/runs/${claims.run_id}/attempts/${claims.run_attempt}`,
            },
            {
              oid: '1.3.6.1.4.1.57264.1.22',
              value: claims.repository_visibility,
            }
          );
          break;
        }
      }

      // Request certificate from CA
      const cert = await ca.issueCertificate({
        publicKey: fromPEM(publicKey),
        subjectAltName: subject,
        extensions,
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
): {
  subject: string;
  issuer: string;
  publicKey: string;
  claims: Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
} {
  const json = JSON.parse(body.toString());
  const { certificateSigningRequest, credentials, publicKeyRequest } = json;
  if (certificateSigningRequest && publicKeyRequest) {
    throw new Error(
      'Invalid request -- cannot specify both CSR and public key'
    );
  } else if (!certificateSigningRequest && !publicKeyRequest) {
    throw new Error('Invalid request -- must specify either CSR or public key');
  } else if (!credentials || !credentials.oidcIdentityToken) {
    throw new Error('Invalid request -- missing OIDC identity token');
  }

  const pem = (() => {
    if (certificateSigningRequest) {
      const csr = new x509.Pkcs10CertificateRequest(certificateSigningRequest);
      return csr.publicKey.toString('pem');
    } else {
      return publicKeyRequest.publicKey.content;
    }
  })();
  const oidc = credentials.oidcIdentityToken;

  // Decode the JWT
  /* eslint-disable @typescript-eslint/no-explicit-any */
  const claims = jose.decodeJwt(oidc) as Record<string, any>;

  /* istanbul ignore next */
  return {
    subject: claims[subjectClaim] || DEFAULT_SUBJECT,
    issuer: claims['iss'] || DEFAULT_ISSUER,
    publicKey: pem,
    claims,
  };
}

function stubBody(): {
  subject: string;
  issuer: string;
  publicKey: string;
  claims: Record<string, any>;
} {
  const { publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  return {
    subject: DEFAULT_SUBJECT,
    issuer: DEFAULT_ISSUER,
    publicKey: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    claims: {
      sub: DEFAULT_SUBJECT,
      iss: DEFAULT_ISSUER,
    },
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
