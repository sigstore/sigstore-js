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

const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';

async function cli(args: string[]) {
  switch (args[0]) {
    case 'sign':
      await sign(args[1]);
      break;
    case 'attest':
      await attest(args[1], args[2]);
      break;
    case 'verify':
      await verify(args[1], args[2]);
      break;
    case 'version':
    case '-version':
    case '--version':
    case '-v':
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      console.log(require('../../package.json').version);
      break;
    case 'help':
    case '--help':
    case '-h':
    case '-?':
      printUsage();
      break;
    default:
      throw 'Unknown command';
  }
}

function printUsage() {
  console.log(`sigstore <command> <artifact>

  Usage:

  sigstore sign         sign an artifact
  sigstore attest       sign an artifact using dsse (Dead Simple Signing Envelope)
  sigstore verify       verify an artifact
  sigstore version      print version information
  sigstore help         print help information
  `);
}

const signOptions = {
  oidcClientID: 'sigstore',
  oidcIssuer: 'https://oauth2.sigstore.dev/auth',
  oidcRedirectURL: process.env.OIDC_REDIRECT_URL,
  rekorURL: sigstore.DEFAULT_REKOR_URL,
};

async function sign(artifactPath: string) {
  const buffer = fs.readFileSync(artifactPath);
  const bundle = await sigstore.sign(buffer, signOptions);

  const url = `${signOptions.rekorURL}/api/v1/log/entries`;
  const logIndex = bundle.verificationMaterial?.tlogEntries[0].logIndex;
  console.error(`Created entry at index ${logIndex}, available at`);
  console.error(`${url}?logIndex=${logIndex}`);

  console.log(JSON.stringify(bundle));
}

async function attest(artifactPath: string, payloadType = INTOTO_PAYLOAD_TYPE) {
  const buffer = fs.readFileSync(artifactPath);
  const bundle = await sigstore.attest(buffer, payloadType, signOptions);
  console.log(JSON.stringify(bundle));
}

async function verify(bundlePath: string, artifactPath: string) {
  let payload: Buffer | undefined = undefined;

  if (artifactPath) {
    payload = fs.readFileSync(artifactPath);
  }

  const bundleFile = fs.readFileSync(bundlePath);
  const bundle: sigstore.Bundle = JSON.parse(bundleFile.toString('utf-8'));

  try {
    await sigstore.verify(bundle, payload, {});
    console.error('Verified OK');
  } catch (e) {
    console.error('Verification failed');
    if (e instanceof Error) {
      console.error('Error: ' + e.message);
    }
    process.exit(1);
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
