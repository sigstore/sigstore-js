import '../../@types/jest/index.d.ts';

const result = (pass: boolean, msg: string) => ({ pass, message: () => msg });
const pass = (msg: string) => result(true, msg);
const fail = (msg: string) => result(false, msg);

const customMatchersObj = {
  // The promise attribute is necessary for the type checking to work correctly
  // in the matchers below. It is not used in the matchers themselves as the
  // functions are invoked with `this` bound to the Jest matchers object.
  promise: undefined,

  // Matcher for checking that a function throws an error of a specific type
  // with a specific `code` property
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  toThrowWithCode(received: any, type: any, code: string) {
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
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
  },
};

// Strip out the dummy `promise` attribute from the custom matchers object
// before passing it to Jest's `expect.extend` function
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const { promise: _, ...customMatchers } = customMatchersObj;
expect.extend(customMatchers);

// Export something so we look like a an importable module
export {};
