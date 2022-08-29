/*
Copyright 2022 The Sigstore Authors.

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
import fs from 'fs';
import { sigstore } from '../index';
import * as enc from '../encoding';

const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';

async function cli(args: string[]) {
  switch (args[0]) {
    case 'sign':
      await sign(args[1]);
      break;
    case 'sign-dsse':
      await signDSSE(args[1], args[2]);
      break;
    case 'verify':
      await verify(args[1], args[2]);
      break;
    case 'verify-dsse':
      await verifyDSSE(args[1]);
      break;
    default:
      throw 'Unknown command';
  }
}

const signOptions = {
  oidcClientID: 'sigstore',
  oidcIssuer: 'https://oauth2.sigstore.dev/auth',
};

async function sign(artifactPath: string) {
  const buffer = fs.readFileSync(artifactPath);
  const bundle = await sigstore.sign(buffer, signOptions);
  console.log(JSON.stringify(bundle));

  const url = `${sigstore.getRekorBaseUrl(signOptions)}/api/v1/log/entries`;
  console.error(`Created entry at index ${bundle.logIndex}, available at`);
  console.error(`${url}?logIndex=${bundle.logIndex}`);
}

async function signDSSE(
  artifactPath: string,
  payloadType = INTOTO_PAYLOAD_TYPE
) {
  const buffer = fs.readFileSync(artifactPath);
  const bundle = await sigstore.signAttestation(
    buffer,
    payloadType,
    signOptions
  );
  console.log(JSON.stringify(bundle));
}

async function verify(artifactPath: string, bundlePath: string) {
  const payload = fs.readFileSync(artifactPath);
  const bundleFile = fs.readFileSync(bundlePath);
  const bundle = JSON.parse(bundleFile.toString('utf-8'));

  const sig = bundle.attestation.signature;
  const cert = enc.base64Decode(bundle.certificate);
  const result = await sigstore.verify(payload, sig, cert);

  if (result) {
    console.error('Verified OK');
  } else {
    throw 'Signature verification failed';
  }
}

async function verifyDSSE(bundlePath: string) {
  const bundleFile = fs.readFileSync(bundlePath);
  const bundle = JSON.parse(bundleFile.toString('utf-8'));
  const result = await sigstore.verifyDSSE(bundle);

  if (result) {
    console.error('Verified OK');
  } else {
    throw 'Signature verification failed';
  }
}

export async function processArgv(): Promise<void> {
  try {
    await cli(process.argv.slice(2));
    process.exit(0);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}
