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
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseImageName } from './name';

export type Credentials = {
  readonly username: string;
  readonly password: string;
};

type DockerConifg = {
  credsStore?: string,
  auths?: { [registry: string]: { auth: string; identitytoken?: string } },
  credHelpers?: { [registry: string]: string },
};

// Returns the credentials for a given registry by reading the Docker config
function credentialFromAuths(dockerConfig: DockerConifg, registry: string) {
  const credKey =
    Object.keys(dockerConfig?.auths || {}).find((key) =>
      key.includes(registry)
    ) || registry;
  const creds = dockerConfig?.auths?.[credKey];

  if (!creds) {
    return null;
  }

  // Extract username/password from auth string
  const { username, password } = fromBasicAuth(creds.auth);

  // If the identitytoken is present, use it as the password (primarily for ACR)
  const pass = creds.identitytoken ? creds.identitytoken : password;

  return { username, password: pass };
}

function credentialFromCredHelpers(dockerConfig: DockerConifg, registry: string) {
  // Check if the registry has a credHelper and use it if it does
  const helper = dockerConfig?.credHelpers?.[registry];

  if (!helper) {
    return null;
  }

  return launchHelper(helper, registry);
}

function credentialFromCredsStore(dockerConfig: DockerConifg, registry: string) {
  // If the credsStore is set, use it to get the credentials
  const helper = dockerConfig?.credsStore;

  if (!helper) {
    return null;
  }

  return launchHelper(helper, registry);
}

function launchHelper(helper: string, registry: string) {
  // Get the credentials from the helper.
  // Parameter for helper is 'get' and registry is passed as input
  // The helper should return a JSON object with the keys "Username" and "Secret"
  try {
    const output = execFileSync(`docker-credential-${helper}`, ["get"], {
      input: registry,
    }).toString();

    const { Username: username, Secret: password } = JSON.parse(output);

    return { username, password };
  } catch (err) {
    throw new Error(`Failed to get credentials from helper ${helper} for registry ${registry}: ${err}`);
  }
}

// file.
export const getRegistryCredentials = (imageName: string): Credentials => {
  const { registry } = parseImageName(imageName);
  const dockerConfigFile = path.join(os.homedir(), '.docker', 'config.json');

  let content: string | undefined;
  try {
    content = fs.readFileSync(dockerConfigFile, 'utf8');
  } catch (err) {
    throw new Error(`No credential file found at ${dockerConfigFile}`);
  }

  const dockerConfig: DockerConifg = JSON.parse(content);

  const fromAuths=credentialFromAuths(dockerConfig, registry);
  if (fromAuths) {
    return fromAuths;
  }
  const fromCredHelpers=credentialFromCredHelpers(dockerConfig, registry);
  if (fromCredHelpers) {
    return fromCredHelpers;
  }
  const fromCredsStore=credentialFromCredsStore(dockerConfig, registry);
  if (fromCredsStore) {
    return fromCredsStore;
  }
  throw new Error(`No credentials found for registry ${registry}`);
};

// Encode the username and password as base64-encoded basicauth value
export const toBasicAuth = (creds: Credentials): string =>
  Buffer.from(`${creds.username}:${creds.password}`).toString('base64');

// Decode the base64-encoded basicauth value
export const fromBasicAuth = (auth: string): Credentials => {
  // Need to account for the possibility of ':' in the password
  const [username, ...rest] = Buffer.from(auth, 'base64').toString().split(':');
  const password = rest.join(':');

  return { username, password };
};
