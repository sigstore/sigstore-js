/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-namespace */

/// <reference types="jest" />

// TS typings for custom Jest matchers in jest.setup.js
declare namespace jest {
  interface Matchers<R> {
    toThrowWithCode(
      type:
        | (new (...args: any[]) => { code: string })
        | (abstract new (...args: any[]) => { code: string })
        | ((...args: any[]) => { code: string }),
      code: string
    ): R;
  }
}
