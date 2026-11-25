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
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  fromBasicAuth,
  getRegistryCredentials,
  toBasicAuth,
} from '../credentials';

describe('getRegistryCredentials', () => {
  const registryName = 'my-registry';
  const imageName = `${registryName}/my-image`;
  let homedirSpy: jest.SpyInstance<string, []> | undefined;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'get-reg-creds-'));
  const dockerDir = path.join(tempDir, '.docker');
  fs.mkdirSync(dockerDir, { recursive: true });

  beforeEach(() => {
    homedirSpy = jest.spyOn(os, 'homedir');
    homedirSpy.mockReturnValue(tempDir);
  });

  afterEach(() => {
    homedirSpy?.mockRestore();
  });

  afterAll(() => {
    fs.rmSync(tempDir, { recursive: true });
  });

  describe('when there is no credentials file', () => {
    it('throws an error', () => {
      expect(() => getRegistryCredentials(imageName)).toThrow(
        /no credential file found/i
      );
    });
  });

  describe('when the creds file is malformed', () => {
    const dockerConfig = {};

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('throws an error', () => {
      expect(() => getRegistryCredentials(imageName)).toThrow(
        /no credentials found for/i
      );
    });
  });

  describe('when there are no creds for the registry', () => {
    const dockerConfig = {
      auths: {},
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('throws an error', () => {
      expect(() => getRegistryCredentials(imageName)).toThrow(
        /no credentials found for/i
      );
    });
  });

  describe('when credentials exist for the registry', () => {
    const username = 'username';
    const password = 'password';
    const headers = { 'X-Api-Key': 'apikey' };
    const dockerConfig = {
      auths: {
        [registryName]: {
          auth: Buffer.from(`${username}:${password}`).toString('base64'),
        },
      },
      HttpHeaders: headers,
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('returns the credentials', () => {
      const creds = getRegistryCredentials(imageName);

      expect(creds).toEqual({ username, password, headers });
    });
  });

  describe('when credentials specify an identity token', () => {
    const username = 'username';
    const password = 'password';
    const token = 'identitytoken';
    const dockerConfig = {
      auths: {
        [registryName]: {
          auth: Buffer.from(`${username}:${password}`).toString('base64'),
          identitytoken: token,
        },
      },
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('returns the credentials', () => {
      const creds = getRegistryCredentials(imageName);

      expect(creds).toEqual({ username, password: token });
    });
  });

  describe('when credentials exist for the registry (partial match)', () => {
    const username = 'username';
    const password = 'password';
    const dockerConfig = {
      auths: {
        [`https://${registryName}/v1`]: {
          auth: Buffer.from(`${username}:${password}`).toString('base64'),
        },
      },
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('returns the credentials', () => {
      const creds = getRegistryCredentials(imageName);

      expect(creds).toEqual({ username, password });
    });
  });

  describe('when the registry is a substring of a configured registry', () => {
    const username = 'victim-user';
    const password = 'victim-pass';
    // The target registry ("cr.io") is a substring of the configured
    // registry ("ghcr.io") but is NOT the same registry.
    const dockerConfig = {
      auths: {
        'ghcr.io': {
          auth: Buffer.from(`${username}:${password}`).toString('base64'),
        },
      },
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('does not leak the unrelated credentials', () => {
      expect(() => getRegistryCredentials('cr.io/attacker/repo')).toThrow(
        /no credentials found for/i
      );
    });
  });

  describe('when a configured registry is a substring of the target registry', () => {
    const username = 'victim-user';
    const password = 'victim-pass';
    // The configured registry ("127.0.0.1:5000") is a substring of the target
    // registry ("victim.127.0.0.1:5000") but is NOT the same registry.
    const dockerConfig = {
      auths: {
        '127.0.0.1:5000': {
          auth: Buffer.from(`${username}:${password}`).toString('base64'),
        },
      },
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('does not leak the unrelated credentials', () => {
      expect(() =>
        getRegistryCredentials('victim.127.0.0.1:5000/attacker/repo')
      ).toThrow(/no credentials found for/i);
    });
  });

  describe('when the target registry includes a port', () => {
    const username = 'username';
    const password = 'password';
    const dockerConfig = {
      auths: {
        'localhost:5000': {
          auth: Buffer.from(`${username}:${password}`).toString('base64'),
        },
      },
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('returns the credentials for the matching host and port', () => {
      const creds = getRegistryCredentials('localhost:5000/my-image');

      expect(creds).toEqual({ username, password });
    });
  });

  describe('when credentials are stored under a Docker Hub alias', () => {
    const username = 'username';
    const password = 'password';
    const dockerConfig = {
      auths: {
        'https://index.docker.io/v1/': {
          auth: Buffer.from(`${username}:${password}`).toString('base64'),
        },
      },
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('returns the credentials for the canonical Docker Hub host', () => {
      const creds = getRegistryCredentials('docker.io/library/my-image');

      expect(creds).toEqual({ username, password });
    });
  });

  describe('when DOCKER_CONFIG points at a custom directory', () => {
    const username = 'custom-user';
    const password = 'custom-pass';
    let customRoot: string;
    let previousDockerConfig: string | undefined;

    beforeEach(() => {
      previousDockerConfig = process.env.DOCKER_CONFIG;
      customRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'oci-docker-config-'));
      fs.writeFileSync(
        path.join(customRoot, 'config.json'),
        JSON.stringify({
          auths: {
            [registryName]: {
              auth: Buffer.from(`${username}:${password}`).toString('base64'),
            },
          },
        })
      );
      process.env.DOCKER_CONFIG = customRoot;
    });

    afterEach(() => {
      if (previousDockerConfig === undefined) {
        delete process.env.DOCKER_CONFIG;
      } else {
        process.env.DOCKER_CONFIG = previousDockerConfig;
      }
      fs.rmSync(customRoot, { recursive: true, force: true });
    });

    it('reads credentials from $DOCKER_CONFIG/config.json', () => {
      const creds = getRegistryCredentials(imageName);

      expect(creds).toEqual({ username, password });
    });

    it('does not fall back to $HOME/.docker when DOCKER_CONFIG is set', () => {
      // Default home config still has credentials from other tests' shared tempDir;
      // ensure we would have found them if we fell back, then assert custom wins.
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify({
          auths: {
            [registryName]: {
              auth: Buffer.from('home-user:home-pass').toString('base64'),
            },
          },
        })
      );

      const creds = getRegistryCredentials(imageName);

      expect(creds).toEqual({ username, password });
    });
  });

  describe('when DOCKER_CONFIG is set but the config file is missing', () => {
    let customRoot: string;
    let previousDockerConfig: string | undefined;

    beforeEach(() => {
      previousDockerConfig = process.env.DOCKER_CONFIG;
      customRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'oci-docker-config-missing-'));
      process.env.DOCKER_CONFIG = customRoot;
    });

    afterEach(() => {
      if (previousDockerConfig === undefined) {
        delete process.env.DOCKER_CONFIG;
      } else {
        process.env.DOCKER_CONFIG = previousDockerConfig;
      }
      fs.rmSync(customRoot, { recursive: true, force: true });
    });

    it('throws rather than falling back to $HOME/.docker', () => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify({
          auths: {
            [registryName]: {
              auth: Buffer.from('home-user:home-pass').toString('base64'),
            },
          },
        })
      );

      expect(() => getRegistryCredentials(imageName)).toThrow(
        /no credential file found/i
      );
    });
  });

});

describe('toBasicAuth', () => {
  const creds = { username: 'user', password: 'pass' };
  const expected = 'dXNlcjpwYXNz';

  it('encodes credentials as base64-encoded basicauth value', () => {
    const result = toBasicAuth(creds);
    expect(result).toEqual(expected);
  });
});

describe('fromBasicAuth', () => {
  const auth = 'dXNlcjpwYXNz';
  const expected = { username: 'user', password: 'pass' };

  it('decodes base64-encoded basicauth value', () => {
    const result = fromBasicAuth(auth);
    expect(result).toEqual(expected);
  });
});
