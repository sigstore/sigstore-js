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
type TUFErrorCode =
  | 'TUF_INIT_CACHE_ERROR'
  | 'TUF_FIND_TARGET_ERROR'
  | 'TUF_REFRESH_METADATA_ERROR'
  | 'TUF_DOWNLOAD_TARGET_ERROR'
  | 'TUF_READ_TARGET_ERROR';

export class TUFError extends Error {
  code: TUFErrorCode;
  override cause: any | undefined;

  constructor({
    code,
    message,
    cause,
  }: {
    code: TUFErrorCode;
    message: string;
    cause?: any;
  }) {
    super(message);
    this.code = code;
    this.cause = cause;
    this.name = this.constructor.name;
  }
}
