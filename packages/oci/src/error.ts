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
import type { Response } from './fetch';

export class HTTPError extends Error {
  readonly statusCode: number;

  constructor({ status, message }: { status: number; message: string }) {
    super(message);
    this.statusCode = status;
  }
}

// Inspects the response status and throws an HTTPError if it does not match the
// expected status code
export const ensureStatus = (
  expectedStatus: number
): ((response: Response) => Response) => {
  return (response: Response): Response => {
    if (response.status !== expectedStatus) {
      throw new HTTPError({
        message: `Error fetching ${response.url} - expected ${expectedStatus}, received ${response.status}`,
        status: response.status,
      });
    }
    return response;
  };
};

export class OCIError extends Error {
  cause: any; /* eslint-disable-line @typescript-eslint/no-explicit-any */

  constructor({
    message,
    cause,
  }: {
    message: string;
    cause?: any /* eslint-disable-line @typescript-eslint/no-explicit-any */;
  }) {
    super(message);
    this.cause = cause;
    this.name = this.constructor.name;
  }
}
