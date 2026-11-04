# @sigstore/jest

Custom Jest matchers and test utilities used across the Sigstore JavaScript projects.
This is a private package and is not published to the registry.

## Installation

```
npm install --save-dev @sigstore/jest
```

Installing this package will also install the `@types/sigstore-jest-extended`
package which gives you access to the TypeScript types for the custom matchers.

## Setup

To install specific matchers, create a Jest setup file (`jest.setup.ts`) with
the following:

```typescript
import { toThrowWithCode } from '@sigstore/jest';
expect.extend({ toThrowWithCode });
```

To automatically extend `expect` will all matchers you can add the following to
the `setupFilesAfterEnv` property in the `jest.config.js` file:

```javascript
module.exports = {
  setupFilesAfterEnv: ['@sigstore/jest/all'],
};
```

or in the `package.json`:

```json
"jest": {
  "setupFilesAfterEnv": ["@sigtore/jest/all"]
}
```

## Restore Nock after TUF mock tests

`@tufjs/repo-mock` activates a Nock interceptor. Restore it after the test file
to avoid affecting later test suites:

```typescript
import { restoreNock } from '@sigstore/jest';

afterAll(() => restoreNock(require.resolve('@tufjs/repo-mock')));
```

The helper resolves Nock relative to the supplied package, so it restores the
correct instance when multiple versions are installed.
