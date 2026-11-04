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
const { generateKeyPairSync, verify, X509Certificate } = require('node:crypto');
const { createRequire } = require('node:module');
const { join } = require('node:path');
const { cwd } = require('node:process');
const { test } = require('node:test');
const pkijs = require('pkijs');

// Resolve the package from the consumer directory rather than the test file.
const requireFromCwd = createRequire(join(cwd(), 'package.json'));
const {
  fulcioHandler,
  initializeCA,
  initializeCTLog,
  initializeTLog,
  initializeTSA,
} = requireFromCwd('@sigstore/mock');

test('the CommonJS entry point issues signing certificates', async () => {
  const keyPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ca = await initializeCA(keyPair);
  const handler = fulcioHandler(ca, { strict: false });
  const result = await handler.fn('');

  assert.equal(result.statusCode, 201);
  const { certificates } = JSON.parse(result.response)
    .signedCertificateEmbeddedSct.chain;
  const leaf = new X509Certificate(certificates[0]);
  const root = new X509Certificate(certificates[1]);
  assert.equal(root.verify(keyPair.publicKey), true);
  assert.equal(leaf.verify(root.publicKey), true);
});

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

test('CommonJS can issue a certificate with an SCT', async () => {
  const keyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ctLog = await initializeCTLog(keyPair);
  const ca = await initializeCA(keyPair, ctLog);
  const certificate = new X509Certificate(
    await ca.issueCertificate({
      publicKey: keyPair.publicKey.export({ format: 'der', type: 'spki' }),
      subjectAltName: 'https://example.com/identity',
    })
  );
  const root = new X509Certificate(ca.rootCertificate);

  assert.ok(certificate.verify(root.publicKey));
  assert.ok(certificate.publicKey.equals(keyPair.publicKey));
  assert.equal(certificate.subjectAltName, 'URI:https://example.com/identity');
  const parsed = pkijs.Certificate.fromBER(certificate.raw);
  assert.ok(
    parsed.extensions.some(
      (extension) => extension.extnID === '1.3.6.1.4.1.11129.2.4.2'
    )
  );
});

test('CommonJS can create a signed timestamp', async () => {
  const keyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const tsa = await initializeTSA(keyPair);
  const result = await tsa.timestamp({
    hashAlgorithmOID: '2.16.840.1.101.3.4.2.1',
    artifactHash: Buffer.alloc(32),
    nonce: 12345,
    policyOID: '1.3.6.1.4.1.57264.2',
    certReq: true,
  });
  const timestamp = pkijs.TimeStampResp.fromBER(result);

  assert.equal(timestamp.status.status, 0);
  assert.equal(timestamp.timeStampToken.contentType, '1.2.840.113549.1.7.2');
  const signedData = new pkijs.SignedData({
    schema: timestamp.timeStampToken.content,
  });
  assert.equal(signedData.certificates.length, 1);
  assert.ok(
    signedData.signerInfos[0].signature.valueBlock.valueHexView.length > 0
  );
  assert.ok(
    new X509Certificate(tsa.intCertificate).verify(
      new X509Certificate(tsa.rootCertificate).publicKey
    )
  );
});
