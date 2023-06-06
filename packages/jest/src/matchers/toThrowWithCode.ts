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

const result = (pass: boolean, msg: string) => ({ pass, message: () => msg });
const pass = (msg: string) => result(true, msg);
const fail = (msg: string) => result(false, msg);

// Matcher for checking that a function throws an error of a specific type
// with a specific `code` property
export function toThrowWithCode(
  this: any,
  received: any,
  type: any,
  code: string
) {
  const isFromReject = this && this.promise === 'rejects';

  // Must be called with either a rejected promise, or a function to be
  // invoked
  if ((!received || typeof received !== 'function') && !isFromReject) {
    return fail(`Excpected ${received} to be a function`);
  }

  // Type must be some kind of class (e.g. Error)
  if (!type || typeof type !== 'function') {
    return fail(`Type argument must be a function, received ${type}`);
  }

  if (typeof code !== 'string') {
    return fail(`Code argument must be a string, received ${code}`);
  }

  // Gather the error, either from the rejected promise or by invoking the
  // supplied function
  let error: (object & { code?: string; name?: string }) | null = null;
  if (isFromReject) {
    error = received;
  } else {
    try {
      received();
    } catch (e) {
      error = e as object;
    }
  }

  if (!error) {
    return fail(`Received function did not throw`);
  }

  if (!(error instanceof type)) {
    return fail(
      `Expected function to throw ${type.name}, but got ${error.name}`
    );
  }

  if (error.code !== code) {
    return fail(
      `Expected error to have code "${code}", but got "${error.code}"`
    );
  }
  return pass(`Expected function to throw ${type.name} with code ${code}`);
}
