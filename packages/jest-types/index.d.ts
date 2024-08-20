/* eslint-disable @typescript-eslint/no-explicit-any */

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
