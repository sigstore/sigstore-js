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

import { HTTPError } from './external/error';

/* eslint-disable @typescript-eslint/no-explicit-any */
type InternalErrorCode =
  | 'TLOG_FETCH_ENTRY_ERROR'
  | 'TLOG_CREATE_ENTRY_ERROR'
  | 'CA_CREATE_SIGNING_CERTIFICATE_ERROR'
  | 'TSA_CREATE_TIMESTAMP_ERROR'
  | 'IDENTITY_TOKEN_READ_ERROR'
  | 'IDENTITY_TOKEN_PARSE_ERROR';

export class InternalError extends Error {
  code: InternalErrorCode;
  override cause: any | undefined;

  constructor({
    code,
    message,
    cause,
  }: {
    code: InternalErrorCode;
    message: string;
    cause?: any;
  }) {
    super(message);
    this.name = this.constructor.name;
    this.cause = cause;
    this.code = code;
  }
}

export function internalError(
  err: unknown,
  code: InternalErrorCode,
  message: string
): never {
  if (err instanceof HTTPError) {
    message += ` - ${err.message}`;
  }

  throw new InternalError({
    code: code,
    message: message,
    cause: err,
  });
}
