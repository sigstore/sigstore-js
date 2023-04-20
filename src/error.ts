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
/* eslint-disable @typescript-eslint/no-explicit-any */
class BaseError extends Error {
  cause: any | undefined;

  constructor(message: string, cause?: any) {
    super(message);
    this.name = this.constructor.name;
    this.cause = cause;
  }
}

export class VerificationError extends BaseError {}

export class ValidationError extends BaseError {}

export class PolicyError extends BaseError {}

type InternalErrorCode =
  | 'TLOG_FETCH_ENTRY_ERROR'
  | 'TLOG_CREATE_ENTRY_ERROR'
  | 'CA_CREATE_SIGNING_CERTIFICATE_ERROR'
  | 'TUF_FIND_TARGET_ERROR'
  | 'TUF_REFRESH_METADATA_ERROR'
  | 'TUF_DOWNLOAD_TARGET_ERROR'
  | 'TUF_READ_TARGET_ERROR';

export class InternalError extends BaseError {
  code: InternalErrorCode;

  constructor({
    code,
    message,
    cause,
  }: {
    code: InternalErrorCode;
    message: string;
    cause?: any;
  }) {
    super(message, cause);
    this.code = code;
  }
}
