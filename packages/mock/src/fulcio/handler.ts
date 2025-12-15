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

import x509 from '@peculiar/x509';
import assert from 'assert';
import { generateKeyPairSync } from 'crypto';
import * as jose from 'jose';
import type { Handler, HandlerFn, HandlerFnResult } from '../shared.types';
import type { CA, ExtensionValue } from './ca';

const CREATE_SIGNING_CERT_PATH = '/api/v2/signingCert';
const DEFAULT_SUBJECT = 'NO-SUBJECT';
const DEFAULT_ISSUER = 'https://fake.oidcissuer.com';

const ISSUER_EXT_OID_V1 = '1.3.6.1.4.1.57264.1.1';
const GH_WORKFLOW_TRIGGER_EXT_OID = '1.3.6.1.4.1.57264.1.2';
const GH_WORKFLOW_SHA_EXT_OID = '1.3.6.1.4.1.57264.1.3';
const GH_WORKFLOW_NAME_EXT_OID = '1.3.6.1.4.1.57264.1.4';
const GH_WORKFLOW_REPO_EXT_OID = '1.3.6.1.4.1.57264.1.5';
const GH_WORKFLOW_REF_EXT_OID = '1.3.6.1.4.1.57264.1.6';
const ISSUER_EXT_OID_V2 = '1.3.6.1.4.1.57264.1.8';
const BUILD_SIGNER_URI_EXT_OID = '1.3.6.1.4.1.57264.1.9';
const BUILD_SIGNER_DIGEST_EXT_OID = '1.3.6.1.4.1.57264.1.10';
const RUNNER_ENVIRONMENT_EXT_OID = '1.3.6.1.4.1.57264.1.11';
const SOURCE_REPO_URI_EXT_OID = '1.3.6.1.4.1.57264.1.12';
const SOURCE_REPO_DIGEST_EXT_OID = '1.3.6.1.4.1.57264.1.13';
const SOURCE_REPO_REF_EXT_OID = '1.3.6.1.4.1.57264.1.14';
const SOURCE_REPO_ID_EXT_OID = '1.3.6.1.4.1.57264.1.15';
const SOURCE_REPO_OWNER_URI_EXT_OID = '1.3.6.1.4.1.57264.1.16';
const SOURCE_REPO_OWNER_ID_EXT_OID = '1.3.6.1.4.1.57264.1.17';
const BUILD_CONFIG_URI_EXT_OID = '1.3.6.1.4.1.57264.1.18';
const BUILD_CONFIG_DIGEST_EXT_OID = '1.3.6.1.4.1.57264.1.19';
const BUILD_TRIGGER_EXT_OID = '1.3.6.1.4.1.57264.1.20';
const RUN_INVOCATION_URI_EXT_OID = '1.3.6.1.4.1.57264.1.21';
const SOURCE_REPO_VISIBILITY_EXT_OID = '1.3.6.1.4.1.57264.1.22';

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
      const { subject, publicKey, claims } = strict
        ? parseBody(body, subjectClaim)
        : stubBody();

      const extensions = extensionFromClaims(claims);

      // Request certificate from CA
      const cert = await ca.issueCertificate({
        publicKey: fromPEM(publicKey),
        subjectAltName: subject,
        extensions: extensions,
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
): { subject: string; publicKey: string; claims: Record<string, string> } {
  const json = JSON.parse(body.toString());
  const oidc = json.credentials.oidcIdentityToken;
  const pem = json.publicKeyRequest
    ? json.publicKeyRequest.publicKey.content
    : extractCSRKey(json.certificateSigningRequest);

  // Decode the JWT
  const claims = jose.decodeJwt(oidc) as Record<string, string>;

  /* istanbul ignore next */
  return {
    subject: claims[subjectClaim] || DEFAULT_SUBJECT,
    publicKey: pem,
    claims: { iss: DEFAULT_ISSUER, ...claims },
  };
}

function stubBody(): {
  subject: string;
  publicKey: string;
  claims: Record<string, string>;
} {
  const { publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  return {
    subject: DEFAULT_SUBJECT,
    publicKey: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    claims: { iss: DEFAULT_ISSUER },
  };
}

function buildResponse(
  leaf: ArrayBufferView<ArrayBuffer>,
  root: ArrayBufferView<ArrayBuffer>
): string {
  const body = {
    signedCertificateEmbeddedSct: {
      chain: {
        certificates: [toPEM(leaf), toPEM(root)],
      },
    },
  };
  return JSON.stringify(body);
}

function extensionFromClaims(claims: Record<string, string>): ExtensionValue[] {
  const extensions: ExtensionValue[] = [];
  const baseURL = 'https://github.com';

  for (const [key, value] of Object.entries(claims)) {
    switch (key) {
      case 'iss':
        extensions.push({
          oid: ISSUER_EXT_OID_V1,
          value: value,
          legacy: true,
        });
        extensions.push({ oid: ISSUER_EXT_OID_V2, value: value });
        break;
      case 'event_name':
        extensions.push({
          oid: GH_WORKFLOW_TRIGGER_EXT_OID,
          value: value,
          legacy: true,
        });
        extensions.push({ oid: BUILD_TRIGGER_EXT_OID, value: value });
        break;
      case 'sha':
        extensions.push({
          oid: GH_WORKFLOW_SHA_EXT_OID,
          value: value,
          legacy: true,
        });
        extensions.push({ oid: SOURCE_REPO_DIGEST_EXT_OID, value: value });
        break;
      case 'workflow':
        extensions.push({
          oid: GH_WORKFLOW_NAME_EXT_OID,
          value: value,
          legacy: true,
        });
        break;
      case 'repository':
        extensions.push({
          oid: GH_WORKFLOW_REPO_EXT_OID,
          value: value,
          legacy: true,
        });
        extensions.push({
          oid: SOURCE_REPO_URI_EXT_OID,
          value: `${baseURL}/${value}`,
        });
        break;
      case 'ref':
        extensions.push({
          oid: GH_WORKFLOW_REF_EXT_OID,
          value: value,
          legacy: true,
        });
        extensions.push({
          oid: SOURCE_REPO_REF_EXT_OID,
          value: value,
        });
        break;
      case 'job_workflow_ref':
        extensions.push({
          oid: BUILD_SIGNER_URI_EXT_OID,
          value: `${baseURL}/${value}`,
        });
        break;
      case 'job_workflow_sha':
        extensions.push({
          oid: BUILD_SIGNER_DIGEST_EXT_OID,
          value: value,
        });
        break;
      case 'runner_environment':
        extensions.push({
          oid: RUNNER_ENVIRONMENT_EXT_OID,
          value: value,
        });
        break;
      case 'repository_id':
        extensions.push({
          oid: SOURCE_REPO_ID_EXT_OID,
          value: value,
        });
        break;
      case 'repository_owner':
        extensions.push({
          oid: SOURCE_REPO_OWNER_URI_EXT_OID,
          value: `${baseURL}/${value}`,
        });
        break;
      case 'repository_owner_id':
        extensions.push({
          oid: SOURCE_REPO_OWNER_ID_EXT_OID,
          value: value,
        });
        break;
      case 'workflow_ref':
        extensions.push({
          oid: BUILD_CONFIG_URI_EXT_OID,
          value: `${baseURL}/${value}`,
        });
        break;
      case 'workflow_sha':
        extensions.push({
          oid: BUILD_CONFIG_DIGEST_EXT_OID,
          value: value,
        });
        break;
      case 'repository_visibility':
        extensions.push({
          oid: SOURCE_REPO_VISIBILITY_EXT_OID,
          value: value,
        });
        break;
    }
  }

  if (claims['repository'] && claims['run_id'] && claims['run_attempt']) {
    extensions.push({
      oid: RUN_INVOCATION_URI_EXT_OID,
      value: `${baseURL}/${claims['repository']}/actions/runs/${claims['run_id']}/attempts/${claims['run_attempt']}`,
    });
  }

  return extensions;
}

function extractCSRKey(pem: string): string {
  const csr = new x509.Pkcs10CertificateRequest(pem);
  return csr.publicKey.toString('pem');
}

// PEM string to DER-encoded byte buffer conversion
function fromPEM(pem: string): ArrayBufferView<ArrayBuffer> {
  return Buffer.from(
    pem.replace(/-{5}(BEGIN|END) .*-{5}/gm, '').replace(/\s/gm, ''),
    'base64'
  );
}

// DER-encoded byte buffer to PEM string conversion
function toPEM(der: ArrayBufferView<ArrayBuffer>): string {
  return [
    '-----BEGIN CERTIFICATE-----',
    Buffer.from(der.buffer).toString('base64'),
    '-----END CERTIFICATE-----',
    '',
  ].join('\n');
}
