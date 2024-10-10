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
import child_process, { ExecFileSyncOptions } from 'node:child_process';
import path from 'path';
import {
  fromBasicAuth,
  getRegistryCredentials,
  toBasicAuth,
} from '../credentials';

describe('getRegistryCredentials', () => {
  const registryName = 'my-registry';
  const imageName = `${registryName}/my-image`;
  const badRegistryName = 'bad-registry';
  const imageNameBadRegistry = `${badRegistryName}/my-image`;
  let homedirSpy: jest.SpyInstance<string, []> | undefined;
  let execSpy: jest.SpyInstance<string | Buffer, [file: string, args?: readonly string[] | undefined, options?: ExecFileSyncOptions | undefined]> | undefined;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'get-reg-creds-'));
  const dockerDir = path.join(tempDir, '.docker');
  fs.mkdirSync(dockerDir, { recursive: true });

  beforeEach(() => {
    homedirSpy = jest.spyOn(os, 'homedir');
    homedirSpy.mockReturnValue(tempDir);

    execSpy = jest.spyOn(child_process, 'execFileSync');
    execSpy?.mockImplementation((file, args, options) => {
      if (file!=="docker-credential-fake" || args?.length!=1 || args[0]!=="get"){
        throw "Invalid arguments";
      }

      if (options?.input === `${registryName}`) {
        const credentials = {
          Username: 'username',
          Secret: 'password'
        };
        return JSON.stringify(credentials);
      }
      throw "Invalid registry";
    });
  });

  afterEach(() => {
    homedirSpy?.mockRestore();
    execSpy?.mockRestore();
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
    const dockerConfig = {
      auths: {
        [registryName]: {
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

  describe('when credHelper exit in error', () => {
    const dockerConfig = {
      credHelpers: {
        [badRegistryName]: "fake"
      }
    };

    beforeEach(() => {
      fs.writeFileSync(
        path.join(tempDir, '.docker', 'config.json'),
        JSON.stringify(dockerConfig),
        {}
      );
    });

    it('throws an error', () => {
      expect(() => getRegistryCredentials(imageNameBadRegistry)).toThrow(
        /Failed to get credentials from helper fake for registry bad-registry/i
      );
    });
  });


  describe('when credHelper exist for the registry', () => {
    const username = 'username';
    const password = 'password';

    const dockerConfig = {
      credHelpers: {
        [registryName]: "fake"
      }
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

  describe('when credsStore exist', () => {
    const username = 'username';
    const password = 'password';

    const dockerConfig = {
      credsStore: "fake"
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
