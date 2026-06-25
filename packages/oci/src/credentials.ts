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
import { parseImageName } from './name';

export type Credentials = {
  readonly username: string;
  readonly password: string;
  readonly headers?: { [key: string]: string };
};

type DockerConifg = {
  auths?: { [registry: string]: { auth: string; identitytoken?: string } };
  HttpHeaders?: { [key: string]: string };
};

// Well-known aliases for the Docker Hub registry. Docker stores Hub
// credentials under a handful of different keys depending on how the user
// authenticated, so they all need to canonicalize to the same host.
const DOCKER_HUB_ALIASES = new Set([
  'docker.io',
  'index.docker.io',
  'registry-1.docker.io',
]);

// Canonicalizes a registry hostname or a Docker config auth key to a
// comparable host[:port] value by stripping any scheme/path and normalizing
// the well-known Docker Hub aliases.
const canonicalizeRegistry = (value: string): string => {
  // Strip the scheme (e.g. "https://") if present.
  let host = value.replace(/^https?:\/\//, '');
  // Strip any path/query (everything after the first '/').
  host = host.split('/')[0];

  return DOCKER_HUB_ALIASES.has(host) ? 'docker.io' : host;
};

// Returns the credentials for a given registry by reading the Docker config
// file.
export const getRegistryCredentials = (imageName: string): Credentials => {
  const { registry } = parseImageName(imageName);
  const dockerConfigFile = path.join(os.homedir(), '.docker', 'config.json');

  let content: string | undefined;
  try {
    content = fs.readFileSync(dockerConfigFile, 'utf8');
  } catch (err) {
    throw new Error(`No credential file found at ${dockerConfigFile}`, {
      cause: err,
    });
  }

  const dockerConfig: DockerConifg = JSON.parse(content);

  // Select the credential whose registry canonicalizes to exactly the target
  // registry. Exact (rather than substring) matching is required to avoid
  // sending credentials configured for one registry to a different registry
  // whose name happens to be a substring of the configured key.
  const target = canonicalizeRegistry(registry);
  const credKey = Object.keys(dockerConfig.auths || {}).find(
    (key) => canonicalizeRegistry(key) === target
  );
  const creds = credKey ? dockerConfig.auths?.[credKey] : undefined;

  if (!creds) {
    throw new Error(`No credentials found for registry ${registry}`);
  }

  // Extract username/password from auth string
  const { username, password } = fromBasicAuth(creds.auth);

  // If the identitytoken is present, use it as the password (primarily for ACR)
  const pass = creds.identitytoken ? creds.identitytoken : password;

  return { headers: dockerConfig.HttpHeaders, username, password: pass };
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
