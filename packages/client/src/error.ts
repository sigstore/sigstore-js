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

class BaseError<T extends string> extends Error {
  code: T;
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  cause: any | undefined;

  constructor({
    code,
    message,
    cause,
  }: {
    code: T;
    message: string;
    cause?: any /* eslint-disable-line @typescript-eslint/no-explicit-any */;
  }) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.cause = cause;
  }
}

type VerificationErrorCode = 'VERIFICATION_ERROR';

export class VerificationError extends BaseError<VerificationErrorCode> {
  constructor(message: string) {
    super({ code: 'VERIFICATION_ERROR', message });
  }
}

type PolicyErrorCode = 'UNTRUSTED_SIGNER_ERROR';

export class PolicyError extends BaseError<PolicyErrorCode> {}
