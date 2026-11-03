/*
Copyright 2026 The Sigstore Authors.

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

/* global require */
const assert = require('node:assert/strict');
const { Buffer } = require('node:buffer');
const { generateKeyPairSync, verify } = require('node:crypto');
const { createRequire } = require('node:module');
const { join } = require('node:path');
const { cwd } = require('node:process');
const { test } = require('node:test');

// Resolve the package from the consumer directory rather than the test file.
const requireFromCwd = createRequire(join(cwd(), 'package.json'));
const { initializeTLog } = requireFromCwd('@sigstore/mock');

test('the CommonJS entry point signs canonicalized log entries', async () => {
  const keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const tlog = await initializeTLog('https://rekor.example', keyPair);
  const result = await tlog.log({ z: [{ b: 2, a: 1 }], a: 'example' });
  const entry = Object.values(result)[0];

  assert.equal(
    Buffer.from(entry.body, 'base64').toString('utf8'),
    '{"a":"example","z":[{"a":1,"b":2}]}'
  );

  const set = JSON.stringify({
    body: entry.body,
    integratedTime: entry.integratedTime,
    logID: entry.logID,
    logIndex: entry.logIndex,
  });
  const signature = Buffer.from(
    entry.verification.signedEntryTimestamp,
    'base64'
  );
  assert.equal(
    verify('sha256', Buffer.from(set), keyPair.publicKey, signature),
    true
  );
});
