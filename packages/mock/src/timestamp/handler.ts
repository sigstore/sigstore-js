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
import type { Handler, HandlerFn, HandlerFnResult } from '../shared.types';
import type { TSA, TimestampRequest } from './tsa';

const OID_SHA256_ALGO_ID = '2.16.840.1.101.3.4.2.1';
const OID_SHA384_ALGO_ID = '2.16.840.1.101.3.4.2.2';
const OID_SHA512_ALGO_ID = '2.16.840.1.101.3.4.2.3';

const OID_TSA_POLICY = '1.3.6.1.4.1.57264.2';

const DEFAULT_NONCE = 1234567890;

const CREATE_TIMESTAMP_PATH = '/api/v1/timestamp';

interface TSAHandlerOptions {
  strict?: boolean;
}

export function tsaHandler(tsa: TSA, opts: TSAHandlerOptions = {}): Handler {
  return {
    path: CREATE_TIMESTAMP_PATH,
    fn: createTimestampHandler(tsa, opts),
  };
}

function createTimestampHandler(tsa: TSA, opts: TSAHandlerOptions): HandlerFn {
  const strict = opts.strict ?? true;

  return async (body: string): Promise<HandlerFnResult> => {
    try {
      const tsr = strict ? parseRequest(body) : stubRequest();
      const timestamp = await tsa.timestamp(tsr);

      return {
        statusCode: 201,
        response: timestamp,
        contentType: 'application/timestamp-reply',
      };
    } catch (e) {
      assert(e instanceof Error);
      return { statusCode: 400, response: e.message };
    }
  };
}

function parseRequest(body: string): TimestampRequest {
  const json = JSON.parse(body.toString());

  /* istanbul ignore next */
  return {
    artifactHash: Buffer.from(json.artifactHash, 'base64'),
    hashAlgorithmOID: hashToOID(json.hashAlgorithm),
    nonce: json.nonce || DEFAULT_NONCE,
    policyOID: json.tsaPolicyOID || OID_TSA_POLICY,
    certReq: json.certificates ?? false,
  };
}

function stubRequest(): TimestampRequest {
  return {
    artifactHash: Buffer.from('deadbeef', 'hex'),
    hashAlgorithmOID: OID_SHA256_ALGO_ID,
    nonce: DEFAULT_NONCE,
    policyOID: OID_TSA_POLICY,
    certReq: false,
  };
}

function hashToOID(hash: string): string {
  switch (true) {
    /* istanbul ignore next */
    case /512/.test(hash):
      return OID_SHA512_ALGO_ID;
    /* istanbul ignore next */
    case /384/.test(hash):
      return OID_SHA384_ALGO_ID;
    default:
      return OID_SHA256_ALGO_ID;
  }
}
