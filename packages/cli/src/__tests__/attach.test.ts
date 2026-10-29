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
import { Config, Parser } from '@oclif/core';
import {
  attachArtifactToImage,
  getImageDigest,
  getRegistryCredentials,
} from '@sigstore/oci';
import { fromPartial } from '@total-typescript/shoehorn';
import Attach from '../commands/attach';

jest.mock('@sigstore/oci', () => ({
  attachArtifactToImage: jest.fn().mockResolvedValue({ digest: 'sha256:abc' }),
  getImageDigest: jest.fn().mockResolvedValue('sha256:abc'),
  getRegistryCredentials: jest
    .fn()
    .mockReturnValue({ username: 'docker-user', password: 'docker-pass' }),
}));
jest.mock('@sigstore/bundle', () => ({
  bundleFromJSON: jest.fn().mockReturnValue({ mediaType: 'application/json' }),
}));
jest.mock('fs/promises', () => ({
  readFile: jest.fn().mockResolvedValue(Buffer.from('{}')),
}));

describe('attach private origins', () => {
  it('parses repeated origins without consuming the image argument', async () => {
    const result = await Parser.parse(
      [
        '--attestation',
        'package.json',
        '--allow-private-origin',
        'http://localhost:5000',
        '--allow-private-origin',
        'https://auth.internal:8443',
        'localhost:5000/test:latest',
      ],
      { flags: Attach.flags, args: Attach.args }
    );
    expect(result.args['image-uri']).toBe('localhost:5000/test:latest');
    expect(result.flags['allow-private-origin']).toEqual([
      'http://localhost:5000',
      'https://auth.internal:8443',
    ]);
  });

  const origins = ['http://localhost:5000', 'https://auth.internal:8443'];
  const createCommand = (
    image = 'localhost:5000/test:latest',
    credentials: { username?: string; password?: string } = {
      username: 'user',
      password: 'pass',
    }
  ) => {
    class TestAttach extends Attach {
      override parse = jest.fn();
    }
    const command = new TestAttach([], fromPartial<Config>({}));
    command.parse.mockResolvedValue({
      args: { 'image-uri': image },
      flags: {
        attestation: 'bundle.json',
        ...credentials,
        'allow-private-origin': origins,
      },
    });
    jest.spyOn(command, 'logToStderr').mockImplementation(() => undefined);
    return command;
  };

  beforeEach(() => jest.clearAllMocks());

  it('passes the same exact origins to digest lookup and artifact upload', async () => {
    const command = createCommand();
    await command.run();
    const fetchOpts = { allowedPrivateOrigins: origins };
    expect(getImageDigest).toHaveBeenCalledWith(
      expect.objectContaining({ fetchOpts })
    );
    expect(attachArtifactToImage).toHaveBeenCalledWith(
      expect.objectContaining({ fetchOpts })
    );
  });

  it('passes the configuration on digest references without doing a tag lookup', async () => {
    const digest = `sha256:${'a'.repeat(64)}`;
    await createCommand(`localhost:5000/test@${digest}`).run();
    expect(getImageDigest).not.toHaveBeenCalled();
    expect(attachArtifactToImage).toHaveBeenCalledWith(
      expect.objectContaining({
        imageDigest: digest,
        fetchOpts: { allowedPrivateOrigins: origins },
      })
    );
  });

  it.each([{}, { username: 'user' }])(
    'supports Docker-config credentials with scoped origins: %j',
    async (credentials) => {
      await createCommand('localhost:5000/test:latest', credentials).run();
      expect(getRegistryCredentials).toHaveBeenCalledWith(
        'localhost:5000/test'
      );
      expect(getImageDigest).toHaveBeenCalledWith(
        expect.objectContaining({
          credentials: { username: 'docker-user', password: 'docker-pass' },
          fetchOpts: { allowedPrivateOrigins: origins },
        })
      );
    }
  );

  it.each([
    { username: '', password: 'pass' },
    { username: 'user', password: '' },
  ])('reports incomplete Docker credentials: %j', async (credentials) => {
    jest.mocked(getRegistryCredentials).mockReturnValueOnce(credentials);
    await expect(
      createCommand('localhost:5000/test:latest', {}).run()
    ).rejects.toThrow(/Error getting registry credentials/);
    expect(attachArtifactToImage).not.toHaveBeenCalled();
  });

  it('preserves Docker-config failure causes', async () => {
    const error = new Error('synthetic config failure');
    jest.mocked(getRegistryCredentials).mockImplementationOnce(() => {
      throw error;
    });
    await expect(
      createCommand('localhost:5000/test:latest', {}).run()
    ).rejects.toMatchObject({ cause: error });
  });

  it('rejects image references without a tag or digest', async () => {
    await expect(createCommand('localhost:5000/test').run()).rejects.toThrow(
      /No digest found/
    );
    expect(attachArtifactToImage).not.toHaveBeenCalled();
  });
});
