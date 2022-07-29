/*
Copyright 2022 GitHub, Inc

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
import { sigstore, dsse } from '../index';

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
  const signature = await sigstore.sign(buffer, signOptions);
  console.log(signature.base64Signature);
}

async function signDSSE(artifactPath: string, payloadType: string) {
  const buffer = fs.readFileSync(artifactPath);
  const envelope = await dsse.sign(buffer, payloadType, signOptions);
  console.log(JSON.stringify(envelope));
}

async function verify(artifactPath: string, signaturePath: string) {
  const payload = fs.readFileSync(artifactPath);
  const sig = fs.readFileSync(signaturePath);
  const result = await sigstore.verify(payload, sig.toString('utf8'));

  if (result) {
    console.error('Verified OK');
  } else {
    throw 'Signature verification failed';
  }
}

async function verifyDSSE(artifactPath: string) {
  const envelope = fs.readFileSync(artifactPath);
  const result = await dsse.verify(JSON.parse(envelope.toString('utf-8')));

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
