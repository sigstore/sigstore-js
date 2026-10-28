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
import nock from 'nock';
import dns from 'node:dns';
import http from 'node:http';
import {
  AddressInfo,
  getDefaultAutoSelectFamily,
  setDefaultAutoSelectFamily,
} from 'node:net';
import { attachArtifactToImage, getImageDigest, OCIError } from '..';
import fetch from '../fetch';
import { OCIImage } from '../image';
import { validateDestination } from '../network';
import { RegistryClient } from '../registry';

const registry = 'registry.example.com';
const origin = `https://${registry}`;
const realm = 'https://auth.example.com/token';
const credentials = { username: '<token>', password: 'synthetic-password' };
const challenge = (url: string) =>
  `Bearer realm="${url}",service="svc",scope="repository:test:pull"`;

describe('destination and credential policy', () => {
  afterEach(() => nock.cleanAll());

  it.each([307, 308])(
    'rejects cross-origin OAuth %d without fallback',
    async (status) => {
      const source = nock(origin)
        .post('/v2/test/blobs/uploads/')
        .reply(401, '', {
          'WWW-Authenticate': challenge(realm),
        });
      const token = nock('https://auth.example.com')
        .post('/token')
        .reply(status, '', {
          Location: 'https://other.example.com/token',
        });
      const destination = nock('https://other.example.com')
        .post('/token')
        .reply(200, {
          access_token: 'unexpected',
        });
      const fallback = nock('https://auth.example.com')
        .get('/token')
        .query(true)
        .reply(200, {
          token: 'unexpected',
        });
      await expect(
        new RegistryClient(registry, 'test').signIn(credentials)
      ).rejects.toThrow(/credential.*body/i);
      expect(source.isDone() && token.isDone()).toBe(true);
      expect(destination.isDone() || fallback.isDone()).toBe(false);
    }
  );

  it.each([307, 308])(
    'preserves same-origin OAuth %d bodies',
    async (status) => {
      nock(origin)
        .post('/v2/test/blobs/uploads/')
        .reply(401, '', {
          'WWW-Authenticate': challenge(realm),
        });
      const scope = nock('https://auth.example.com')
        .post('/token', /password=synthetic-password/)
        .reply(status, '', { Location: '/final' })
        .post('/final', /password=synthetic-password/)
        .reply(200, { access_token: 'ok' });
      await new RegistryClient(registry, 'test').signIn(credentials);
      expect(scope.isDone()).toBe(true);
    }
  );

  it.each([
    'https://auth.example.com:444/token',
    'https://other.example.com/token',
  ])(
    'rejects a credential body after a same-origin hop to %s',
    async (target) => {
      nock(origin)
        .post('/v2/test/blobs/uploads/')
        .reply(401, '', {
          'WWW-Authenticate': challenge(realm),
        });
      nock('https://auth.example.com')
        .post('/token')
        .reply(307, '', { Location: '/second' })
        .post('/second')
        .reply(308, '', { Location: target });
      await expect(
        new RegistryClient(registry, 'test').signIn(credentials)
      ).rejects.toThrow(/credential.*body/i);
    }
  );

  it.each([301, 302, 303])(
    'allows cross-origin OAuth %d after dropping body',
    async (status) => {
      nock(origin)
        .post('/v2/test/blobs/uploads/')
        .reply(401, '', {
          'WWW-Authenticate': challenge(realm),
        });
      nock('https://auth.example.com').post('/token').reply(status, '', {
        Location: 'https://other.example.com/final',
      });
      const scope = nock('https://other.example.com', {
        badheaders: ['authorization', 'content-type'],
      })
        .get('/final')
        .reply(200, { access_token: 'ok' });
      await new RegistryClient(registry, 'test').signIn(credentials);
      expect(scope.isDone()).toBe(true);
    }
  );

  it('does not restore Basic credentials after leaving and returning to the token origin', async () => {
    nock(origin)
      .post('/v2/test/blobs/uploads/')
      .reply(401, '', {
        'WWW-Authenticate': challenge(realm),
      });
    nock('https://auth.example.com').get('/token').query(true).reply(307, '', {
      Location: 'https://other.example.com/intermediate',
    });
    nock('https://other.example.com', { badheaders: ['authorization'] })
      .get('/intermediate')
      .reply(307, '', { Location: realm + '/final' });
    const scope = nock('https://auth.example.com', {
      badheaders: ['authorization'],
    })
      .get('/token/final')
      .reply(200, { token: 'ok' });
    await new RegistryClient(registry, 'test').signIn({
      username: 'user',
      password: 'pass',
    });
    expect(scope.isDone()).toBe(true);
  });

  it.each([
    'https://127.0.0.1/token',
    'https://10.1.2.3/token',
    'https://169.254.169.254/token',
    'https://100.100.100.200/token',
    'https://[::1]/token',
    'https://[::ffff:7f00:1]/token',
    'https://[fd00:ec2::254]/token',
    'https://[fe80::1]/token',
    'https://2130706433/token',
    'https://0x7f000001/token',
    'ftp://example.com/token',
    'https://user:secret@example.com/token',
    'http://auth.example.com/token',
    'not a URL',
  ])('rejects an unsafe realm before making a request: %s', async (url) => {
    nock(origin)
      .post('/v2/test/blobs/uploads/')
      .reply(401, '', {
        'WWW-Authenticate': challenge(url),
      });
    await expect(
      new RegistryClient(registry, 'test').signIn(credentials)
    ).rejects.toThrow(/network policy/i);
  });

  it('rejects an initial private registry with an OCIError cause in both public APIs', async () => {
    const opts = { imageName: '127.0.0.1:5000/test', credentials };
    for (const result of [
      getImageDigest({ ...opts, imageTag: 'latest' }),
      attachArtifactToImage({
        ...opts,
        imageDigest: 'sha256:abc',
        artifact: Buffer.from('a'),
        mediaType: 'text/plain',
      }),
    ]) {
      await expect(result).rejects.toBeInstanceOf(OCIError);
      await expect(result).rejects.toMatchObject({
        cause: { message: expect.stringMatching(/network policy/i) },
      });
    }
  });

  it('passes a narrowly scoped local exception through the public digest API', async () => {
    const local = 'http://127.0.0.1:5000';
    const scope = nock(local)
      .post('/v2/test/blobs/uploads/')
      .reply(200)
      .head('/v2/test/manifests/latest')
      .reply(200, '', { 'Docker-Content-Digest': 'sha256:abc' });
    await expect(
      getImageDigest({
        imageName: '127.0.0.1:5000/test',
        imageTag: 'latest',
        credentials,
        fetchOpts: { allowedPrivateOrigins: [local] },
      })
    ).resolves.toBe('sha256:abc');
    expect(scope.isDone()).toBe(true);
  });

  it('passes the exception through the public artifact API', async () => {
    const local = 'http://127.0.0.1:5000';
    const scope = nock(local)
      .post('/v2/test/blobs/uploads/')
      .reply(200)
      .head('/v2/test/manifests/sha256:abc')
      .reply(200)
      .head(/\/blobs\//)
      .twice()
      .reply(200)
      .put(/\/manifests\//)
      .reply(201, '', { 'OCI-Subject': 'sha256:abc' })
      .get(/\/referrers\//)
      .reply(200);
    await expect(
      attachArtifactToImage({
        imageName: '127.0.0.1:5000/test',
        imageDigest: 'sha256:abc',
        credentials,
        artifact: Buffer.from('a'),
        mediaType: 'text/plain',
        fetchOpts: { allowedPrivateOrigins: [local] },
      })
    ).resolves.toMatchObject({
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
    });
    expect(scope.isDone()).toBe(true);
  });

  it('does not let a local exception authorize a different private origin', async () => {
    const local = 'http://127.0.0.1:5000';
    nock(local)
      .get('/v2/')
      .reply(307, '', { Location: 'http://127.0.0.1:5001/v2/' });
    await expect(
      new RegistryClient('127.0.0.1:5000', 'test', {
        allowedPrivateOrigins: [local],
      }).checkVersion()
    ).rejects.toThrow(/network policy/i);
  });

  it('rejects a private upload Location', async () => {
    nock(origin)
      .head(/\/blobs\//)
      .reply(404)
      .post('/v2/test/blobs/uploads/')
      .reply(202, '', { Location: 'https://169.254.169.254/upload' });
    await expect(
      new RegistryClient(registry, 'test').uploadBlob(Buffer.from('a'))
    ).rejects.toThrow(/network policy/i);
  });

  it('rejects malformed configuration before sending a request', async () => {
    await expect(
      new RegistryClient(registry, 'test', {
        allowedPrivateOrigins: ['not a URL'],
      }).checkVersion()
    ).rejects.toThrow(/network policy/i);
  });

  it('treats a malformed token redirect as terminal instead of falling back', async () => {
    nock(origin)
      .post('/v2/test/blobs/uploads/')
      .reply(401, '', {
        'WWW-Authenticate': challenge(realm),
      });
    nock('https://auth.example.com').post('/token').reply(307, '', {
      Location: 'https://[',
    });
    const fallback = nock('https://auth.example.com')
      .get('/token')
      .query(true)
      .reply(200, { token: 'unexpected' });
    await expect(
      new RegistryClient(registry, 'test').signIn(credentials)
    ).rejects.toThrow(/network policy.*invalid redirect/i);
    expect(fallback.isDone()).toBe(false);
  });

  it('does not downgrade token requests after an HTTP registry probe upgrades to HTTPS', async () => {
    const local = 'http://127.0.0.1:5000';
    nock(local)
      .post('/v2/test/blobs/uploads/')
      .reply(307, '', {
        Location: origin + '/challenge',
      });
    nock(origin)
      .post('/challenge')
      .reply(401, '', {
        'WWW-Authenticate': challenge(local + '/token'),
      });
    const token = nock(local)
      .post('/token')
      .reply(200, { access_token: 'unexpected' });
    await expect(
      new RegistryClient('127.0.0.1:5000', 'test', {
        allowedPrivateOrigins: [local],
      }).signIn(credentials)
    ).rejects.toThrow(/HTTPS downgrades/i);
    expect(token.isDone()).toBe(false);
  });

  it('preserves Docker Hub cross-origin authentication without exceptions', async () => {
    const hub = nock('https://registry-1.docker.io')
      .post('/v2/library/test/blobs/uploads/')
      .reply(401, '', {
        'WWW-Authenticate': challenge('https://auth.docker.io/token'),
      })
      .head('/v2/library/test/manifests/latest')
      .matchHeader('authorization', 'Bearer ok')
      .reply(200, '', { 'Docker-Content-Digest': 'sha256:abc' });
    const token = nock('https://auth.docker.io')
      .get('/token')
      .query(true)
      .matchHeader('authorization', 'Basic dXNlcjpwYXNz')
      .reply(200, { token: 'ok' });
    await expect(
      getImageDigest({
        imageName: 'docker.io/library/test',
        imageTag: 'latest',
        credentials: { username: 'user', password: 'pass' },
      })
    ).resolves.toBe('sha256:abc');
    expect(hub.isDone() && token.isDone()).toBe(true);
  });

  it('rejects an upload downgrade relative to the effective POST URL, even with an exception', async () => {
    const local = 'http://127.0.0.1:5000';
    nock(local)
      .head(/\/blobs\//)
      .reply(404)
      .post('/v2/test/blobs/uploads/')
      .reply(307, '', { Location: 'https://storage.example.com/session' });
    nock('https://storage.example.com')
      .post('/session')
      .reply(202, '', { Location: local + '/upload' });
    const destination = nock(local).put('/upload').query(true).reply(201);
    await expect(
      new RegistryClient('127.0.0.1:5000', 'test', {
        allowedPrivateOrigins: [local],
      }).uploadBlob(Buffer.from('a'))
    ).rejects.toThrow(/HTTPS downgrades/i);
    expect(destination.isDone()).toBe(false);
  });

  it.each([
    'https://0.0.0.0',
    'https://172.16.0.1',
    'https://192.168.1.1',
    'https://168.63.129.16',
    'https://198.18.0.1',
    'https://224.0.0.1',
    'https://[::]',
    'https://[2001:db8::1]',
    'https://[2002:7f00:1::]',
  ])('blocks non-public/special addresses: %s', (url) => {
    expect(() => validateDestination(url)).toThrow(/network policy/i);
  });

  it.each(['https://8.8.8.8', 'https://[2606:4700:4700::1111]'])(
    'permits public literals: %s',
    (url) => {
      expect(validateDestination(url).origin).toBe(url);
    }
  );

  it.each([
    'https://example.com/path',
    'https://user:secret@example.com',
    'ftp://example.com',
  ])(
    'rejects malformed exceptions without exposing userinfo: %s',
    (exception) => {
      expect(() =>
        validateDestination(origin, { allowedPrivateOrigins: [exception] })
      ).toThrow(/network policy/i);
      try {
        validateDestination(origin, { allowedPrivateOrigins: [exception] });
      } catch (error) {
        expect(String(error)).not.toContain('secret');
      }
    }
  );

  it.each([
    'docker.io',
    'index.docker.io',
    'registry-1.docker.io',
    'mydocker.io',
    'evil.docker.io',
    'docker.io:444',
  ])(
    'only canonicalizes exact unported Docker Hub aliases: %s',
    async (host) => {
      const expected = [
        'docker.io',
        'index.docker.io',
        'registry-1.docker.io',
      ].includes(host)
        ? 'registry-1.docker.io'
        : host;
      const scope = nock(`https://${expected}`)
        .post('/v2/test/blobs/uploads/')
        .reply(200)
        .head('/v2/test/manifests/latest')
        .reply(200, '', { 'Docker-Content-Digest': 'sha256:abc' });
      await new OCIImage(
        { registry: host, path: 'test' },
        credentials
      ).getDigest('latest');
      expect(scope.isDone()).toBe(true);
    }
  );
});

describe('connection-time destination enforcement (real transport)', () => {
  let server: http.Server;
  let port: number;
  let requests: number;
  beforeEach(async () => {
    requests = 0;
    server = http.createServer((_req, res) => {
      requests++;
      res.end('ok');
    });
    await new Promise<void>((resolve) =>
      server.listen(0, '127.0.0.1', resolve)
    );
    port = (server.address() as AddressInfo).port;
  });
  afterEach(async () => {
    jest.restoreAllMocks();
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve()))
    );
  });

  it('blocks DNS resolving to loopback without dialing or retrying', async () => {
    const lookup = jest
      .spyOn(dns, 'lookup')
      .mockImplementation((_host, _opts, callback) => {
        callback(null, [{ address: '127.0.0.1', family: 4 }]);
      });
    await expect(
      fetch(`https://untrusted.example:${port}/`, {
        retry: { retries: 2, minTimeout: 0 },
      })
    ).rejects.toThrow(/network policy/i);
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(requests).toBe(0);
  });

  it('checks every DNS answer, including mapped IPv6', async () => {
    jest.spyOn(dns, 'lookup').mockImplementation((_host, _opts, callback) => {
      callback(null, [
        { address: '93.184.216.34', family: 4 },
        { address: '::ffff:127.0.0.1', family: 6 },
      ]);
    });
    await expect(fetch(`https://untrusted.example:${port}/`)).rejects.toThrow(
      /network policy/i
    );
    expect(requests).toBe(0);
  });

  it.each([
    { addresses: [] },
    { addresses: [{ address: 'not-an-address', family: 4 }] },
  ])(
    'fails closed on empty or invalid DNS results: %j',
    async ({ addresses }) => {
      jest.spyOn(dns, 'lookup').mockImplementation((_host, _opts, callback) => {
        callback(null, addresses);
      });
      await expect(fetch(`https://untrusted.example:${port}/`)).rejects.toThrow(
        /network policy/i
      );
      expect(requests).toBe(0);
    }
  );

  it('propagates ordinary DNS failures without dialing', async () => {
    const error = Object.assign(new Error('synthetic DNS failure'), {
      code: 'ENOTFOUND',
    });
    jest.spyOn(dns, 'lookup').mockImplementation((_host, _opts, callback) => {
      callback(error, []);
    });
    await expect(fetch(`https://untrusted.example:${port}/`)).rejects.toThrow(
      /synthetic DNS failure/i
    );
    expect(requests).toBe(0);
  });

  it('uses the guarded lookup when automatic family selection is disabled', async () => {
    const previous = getDefaultAutoSelectFamily();
    setDefaultAutoSelectFamily(false);
    try {
      jest.spyOn(dns, 'lookup').mockImplementation((_host, _opts, callback) => {
        callback(null, [{ address: '127.0.0.1', family: 4 }]);
      });
      const url = `http://intentional.example:${port}`;
      const response = await fetch(url, { allowedPrivateOrigins: [url] });
      expect(await response.text()).toBe('ok');
      expect(requests).toBe(1);
    } finally {
      setDefaultAutoSelectFamily(previous);
    }
  });

  it('uses the checked DNS result for the actual connection, once per attempt', async () => {
    const lookup = jest
      .spyOn(dns, 'lookup')
      .mockImplementation((_host, _opts, callback) => {
        callback(null, [{ address: '127.0.0.1', family: 4 }]);
      });

    const url = `http://intentional.example:${port}`;
    for (let i = 0; i < 2; i++) {
      const response = await fetch(url, { allowedPrivateOrigins: [url] });
      expect(await response.text()).toBe('ok');
    }
    expect(lookup).toHaveBeenCalledTimes(2);
    expect(requests).toBe(2);
  });

  it('re-resolves through the guarded lookup on retries and does not pool across policies', async () => {
    server.removeAllListeners('request');
    server.on('request', (_req, res) => {
      requests++;
      res.statusCode = requests === 1 ? 500 : 200;
      res.end('ok');
    });
    const lookup = jest
      .spyOn(dns, 'lookup')
      .mockImplementation((_host, _opts, callback) => {
        callback(null, [{ address: '127.0.0.1', family: 4 }]);
      });
    const url = `http://intentional.example:${port}`;
    const response = await fetch(url, {
      allowedPrivateOrigins: [url],
      retry: { retries: 1, minTimeout: 0 },
    });
    expect(await response.text()).toBe('ok');
    expect(lookup).toHaveBeenCalledTimes(2);
    expect(requests).toBe(2);
    await expect(fetch(`https://intentional.example:${port}`)).rejects.toThrow(
      /network policy/i
    );
    expect(requests).toBe(2);
    expect(lookup).toHaveBeenCalledTimes(3);
  });

  describe('proxies', () => {
    const ENV_KEYS = ['HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY'];
    let savedEnv: Record<string, string | undefined>;
    let connects: string[];
    let lookup: jest.SpyInstance;

    beforeEach(() => {
      savedEnv = Object.fromEntries(
        ENV_KEYS.map((key) => [key, process.env[key]])
      );
      connects = [];
      server.on('connect', (req, socket) => {
        connects.push(req.url as string);
        socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      });
      lookup = jest
        .spyOn(dns, 'lookup')
        .mockImplementation((_host, _opts, callback) => {
          callback(null, [{ address: '127.0.0.1', family: 4 }]);
        });
    });
    afterEach(() => {
      for (const key of ENV_KEYS) {
        if (savedEnv[key] === undefined) delete process.env[key];
        else process.env[key] = savedEnv[key];
      }
    });

    const proxyURL = () => `http://127.0.0.1:${port}`;
    const settle = (p: Promise<unknown>) => p.catch(() => undefined);

    it('tunnels through an explicit proxy, even one at a private address', async () => {
      await settle(
        fetch('https://registry.example.com/v2/', { proxy: proxyURL() })
      );
      expect(connects).toEqual(['registry.example.com:443']);
      expect(lookup).not.toHaveBeenCalled();
    });

    it('honors proxy environment variables set after module load', async () => {
      process.env.HTTPS_PROXY = proxyURL();
      await settle(fetch('https://registry.example.com/v2/'));
      expect(connects).toEqual(['registry.example.com:443']);
    });

    it('proxies HTTP to an allowed private origin via HTTP_PROXY', async () => {
      process.env.HTTP_PROXY = proxyURL();
      const origin = 'http://internal.example:5000';
      const response = await fetch(`${origin}/v2/`, {
        allowedPrivateOrigins: [origin],
      });
      expect(await response.text()).toBe('ok');
      expect(requests).toBe(1);
      expect(lookup).not.toHaveBeenCalled();
    });

    it('still applies URL checks to proxied requests', async () => {
      for (const url of [
        'https://169.254.169.254/latest',
        'https://localhost/v2/',
        'https://localhost./v2/',
        'https://auth.localhost./v2/',
        'http://registry.example.com/v2/',
      ]) {
        await expect(fetch(url, { proxy: proxyURL() })).rejects.toThrow(
          /network policy/i
        );
      }
      expect(connects).toEqual([]);
      expect(requests).toBe(0);
    });

    it.each([
      ['NO_PROXY env', undefined, '., example.com'],
      ['noProxy string', 'other.test,example.com', undefined],
      ['noProxy array', ['example.com'], undefined],
      ['uppercase NO_PROXY env', undefined, 'EXAMPLE.COM'],
      ['mixed-case noProxy', ['Registry.Example.Com'], undefined],
    ])(
      'connects directly with DNS enforcement when excluded by %s',
      async (_label, noProxy, env) => {
        process.env.HTTPS_PROXY = proxyURL();
        if (env) process.env.NO_PROXY = env;
        await expect(
          fetch('https://registry.example.com/v2/', { noProxy })
        ).rejects.toThrow(/network policy/i);
        expect(connects).toEqual([]);
        expect(lookup).toHaveBeenCalledTimes(1);
      }
    );

    it('does not exclude unrelated hosts listed in NO_PROXY', async () => {
      process.env.HTTPS_PROXY = proxyURL();
      process.env.NO_PROXY = 'other.example.com';
      await settle(fetch('https://registry.example.com/v2/'));
      expect(connects).toEqual(['registry.example.com:443']);
    });

    it('rejects an invalid proxy URL without connecting', async () => {
      await expect(
        fetch('https://registry.example.com/v2/', { proxy: 'not a url' })
      ).rejects.toThrow(/network policy: invalid proxy URL/i);
      expect(lookup).not.toHaveBeenCalled();
    });
  });
});
