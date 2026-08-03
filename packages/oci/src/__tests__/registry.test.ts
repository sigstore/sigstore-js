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
import nock from 'nock';
import assert from 'node:assert';
import crypto from 'node:crypto';
import {
  CONTENT_TYPE_DOCKER_MANIFEST,
  CONTENT_TYPE_DOCKER_MANIFEST_LIST,
  CONTENT_TYPE_OCI_INDEX,
  CONTENT_TYPE_OCI_MANIFEST,
  CONTENT_TYPE_OCTET_STREAM,
  HEADER_ACCEPT,
  HEADER_API_VERSION,
  HEADER_CONTENT_LENGTH,
  HEADER_CONTENT_TYPE,
  HEADER_DIGEST,
  HEADER_IF_MATCH,
} from '../constants';
import { HTTPError } from '../error';
import { RegistryClient } from '../registry';

describe('RegistryClient', () => {
  const registryName = 'registry.example.com';
  const repoName = 'test';
  const registryURL = `https://${registryName}`;
  const headers = { 'X-Custom-Auth': 'sometoken' };
  const subject = new RegistryClient(registryName, repoName, { retry: false });

  describe('checkVersion', () => {
    describe('when the Api-Version header is avaialble', () => {
      beforeEach(() => {
        nock(registryURL)
          .get('/v2/')
          .reply(200, undefined, {
            [HEADER_API_VERSION]: 'registry/2.0',
          });
      });

      it('returns the version', async () => {
        const version = await subject.checkVersion();
        expect(version).toEqual('registry/2.0');
      });
    });

    describe('when the Api-Version header is NOT avaialble', () => {
      beforeEach(() => {
        nock(registryURL).get('/v2/').reply(200);
      });

      it('returns the empty string', async () => {
        const version = await subject.checkVersion();
        expect(version).toEqual('');
      });
    });
  });

  describe('signIn', () => {
    const creds = { username: 'username', password: 'password', headers };

    describe('when the client is already signed in', () => {
      beforeEach(() => {
        nock(registryURL, { reqheaders: headers })
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(200, undefined, {});
      });

      it('returns without error', async () => {
        await expect(subject.signIn(creds)).resolves.toBeUndefined();
      });
    });

    describe('when the registry uses an unsupported auth scheme', () => {
      const challenge = 'Foo realm="registry.example.com"';
      beforeEach(() => {
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });
      });

      it('throws an error', async () => {
        await expect(subject.signIn(creds)).rejects.toThrow(
          /invalid challenge/i
        );
      });
    });

    describe('when the registry uses basic auth', () => {
      const challenge = 'Basic realm="registry.example.com"';

      beforeEach(() => {
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });
      });

      it('returns without error', async () => {
        await expect(subject.signIn(creds)).resolves.toBeUndefined();
      });
    });

    describe('when the registry uses an OAuth2 bearer token', () => {
      const creds = { username: '<token>', password: 'password' };
      const challenge =
        'Bearer realm="https://registry.example.com/oauth2/token";service="service";scope="scope"';
      const accessToken = 'deadbeef';

      beforeEach(() => {
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          })
          .post('/oauth2/token', {
            service: 'service',
            scope: 'scope',
            grant_type: 'password',
            username: creds.username,
            password: creds.password,
          })
          .reply(200, { access_token: accessToken });
      });

      it('returns without error', async () => {
        await expect(subject.signIn(creds)).resolves.toBeUndefined();
      });
    });

    describe('when the registry uses a bearer token and returns an error', () => {
      const creds = { username: '<token>', password: 'password' };
      const challenge =
        'Bearer realm="https://registry.example.com/oauth2/token";service="service";scope="scope"';
      const accessToken = 'deadbeef';

      beforeEach(() => {
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          })
          .post('/oauth2/token', {
            service: 'service',
            scope: 'scope',
            grant_type: 'password',
            username: creds.username,
            password: creds.password,
          })
          .reply(404, {})
          .get(`/oauth2/token?service=service&scope=scope`)
          .reply(200, { token: accessToken });
      });

      it('returns without error', async () => {
        await expect(subject.signIn(creds)).resolves.toBeUndefined();
      });
    });

    describe('when the registry uses a foundation bearer token', () => {
      const challenge =
        'Bearer realm="https://registry.example.com/token";service="service";scope="scope"';
      const accessToken = 'deadbeef';

      beforeEach(() => {
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          })
          .get(`/token?service=service&scope=scope`)
          .reply(200, { token: accessToken });
      });

      it('returns without error', async () => {
        await expect(subject.signIn(creds)).resolves.toBeUndefined();
      });
    });

    describe('when sign-in probe redirects cross-origin', () => {
      const externalURL = 'https://auth-proxy.example.com';
      const challenge =
        'Basic realm="registry.example.com" service="svc" scope="repo"';

      beforeEach(() => {
        // Probe POST redirects cross-origin (307 preserves POST)
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(307, undefined, {
            Location: `${externalURL}/v2/${repoName}/blobs/uploads/`,
          });

        // Cross-origin target returns the 401 challenge but must NOT see
        // custom Docker headers
        nock(externalURL, {
          badheaders: ['x-custom-auth'],
        })
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });
      });

      it('strips custom headers on cross-origin redirect while preserving challenge behavior', async () => {
        const authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });
        await expect(
          authSubject.signIn({
            username: 'user',
            password: 'pass',
            headers,
          })
        ).resolves.toBeUndefined();
      });
    });

    describe('token exchange does not leak registry defaults to auth realm', () => {
      const authRealmURL = 'https://auth.example.com';
      const challenge = `Bearer realm="${authRealmURL}/token",service="svc",scope="repo:test:pull"`;

      it('distribution token request does not carry registry default headers', async () => {
        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        // Sign in: first probe gets 401, then token exchange
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });

        // Auth realm must NOT receive the custom registry headers
        nock(authRealmURL, {
          badheaders: ['x-custom-auth'],
        })
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull' })
          .matchHeader('authorization', /Basic/)
          .reply(200, { token: 'tok123' });

        await expect(
          tokenSubject.signIn({
            username: 'user',
            password: 'pass',
            headers,
          })
        ).resolves.toBeUndefined();
      });

      it('OAuth2 token request does not carry registry default headers', async () => {
        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });
        const oauthChallenge = `Bearer realm="${authRealmURL}/oauth2/token",service="svc",scope="repo:test:pull"`;

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': oauthChallenge,
          });

        // OAuth realm must NOT receive custom registry headers
        nock(authRealmURL, {
          badheaders: ['x-custom-auth'],
        })
          .post('/oauth2/token')
          .reply(200, { access_token: 'oatk456' });

        await expect(
          tokenSubject.signIn({
            username: '<token>',
            password: 'pass',
            headers,
          })
        ).resolves.toBeUndefined();
      });

      it('distribution token Authorization is stripped on cross-origin redirect', async () => {
        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });
        const redirectTarget = 'https://redirected-auth.example.com';

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });

        // Auth realm redirects cross-origin
        nock(authRealmURL)
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull' })
          .reply(302, undefined, {
            Location: `${redirectTarget}/token-final`,
          });

        // Redirect target must NOT receive Authorization or registry defaults
        nock(redirectTarget, {
          badheaders: ['authorization', 'x-custom-auth'],
        })
          .get('/token-final')
          .reply(200, { token: 'redirected-tok' });

        await expect(
          tokenSubject.signIn({
            username: 'user',
            password: 'pass',
            headers,
          })
        ).resolves.toBeUndefined();
      });

      it('same-origin auth-realm redirect retains explicit Basic Authorization', async () => {
        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });

        // Auth realm redirects to same-origin path — explicit Authorization
        // must be preserved
        nock(authRealmURL)
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull' })
          .matchHeader('authorization', /Basic/)
          .reply(302, undefined, {
            Location: `${authRealmURL}/token-v2`,
          });

        // Same-origin hop MUST still carry the explicit Basic Authorization
        nock(authRealmURL, {
          reqheaders: {
            authorization: /Basic/,
          },
        })
          .get('/token-v2')
          .reply(200, { token: 'same-origin-tok' });

        await expect(
          tokenSubject.signIn({
            username: 'user',
            password: 'pass',
            headers,
          })
        ).resolves.toBeUndefined();
      });
    });
  });

  describe('uploadBlob', () => {
    const blob = Buffer.from('hello world', 'utf8');
    const digest = `sha256:${crypto
      .createHash('sha256')
      .update(blob)
      .digest('hex')}`;

    describe('when everything is successful', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `${registryURL}/v2/${repoName}/blobs/uploads/123`,
          })
          .put(`/v2/${repoName}/blobs/uploads/123?digest=${digest}`)
          .matchHeader(HEADER_CONTENT_TYPE, CONTENT_TYPE_OCTET_STREAM)
          .reply(201);
      });

      it('uploads the blob', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCTET_STREAM);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('when registry returns a relative upload location', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `/v2/${repoName}/blobs/uploads/123`,
          })
          .put(`/v2/${repoName}/blobs/uploads/123?digest=${digest}`)
          .reply(201);
      });

      it('uploads the blob', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCTET_STREAM);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('when Location is path-relative (OCI RFC 7231 compliance)', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            // Path-relative Location must resolve against the POST URL path,
            // NOT the registry root. Expected effective URL:
            // https://registry.example.com/v2/test/blobs/uploads/session-123
            Location: 'session-123',
          })
          .put(
            `/v2/${repoName}/blobs/uploads/session-123?digest=${digest}`
          )
          .reply(201);
      });

      it('resolves the path-relative Location against the POST URL', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCTET_STREAM);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('when Location is path-relative after a redirected POST', () => {
      beforeEach(() => {
        // POST redirects (307 preserves method) to a different path
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(307, undefined, {
            Location: `${registryURL}/v2/${repoName}/blobs/uploads/redirected/`,
          });

        // Redirected POST responds with a path-relative Location
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/redirected/`)
          .reply(202, undefined, {
            // Must resolve against the effective (final) request URL:
            // https://registry.example.com/v2/test/blobs/uploads/redirected/session-456
            Location: 'session-456',
          });

        nock(registryURL)
          .put(
            `/v2/${repoName}/blobs/uploads/redirected/session-456?digest=${digest}`
          )
          .reply(201);
      });

      it('resolves the path-relative Location against the final redirected URL', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('when the blob already exists', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(200, undefined, {
            'Content-Length': blob.length.toString(),
          });
      });

      it('returns the blob digest', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCTET_STREAM);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('when HEAD blob check redirects to storage (same-origin)', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(307, undefined, {
            Location: `${registryURL}/storage/blob-data`,
          })
          .head('/storage/blob-data')
          .reply(200);
      });

      it('follows the redirect to a terminal 200 and returns exists', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCTET_STREAM);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('when HEAD blob check redirects to cross-origin storage', () => {
      const storageURL = 'https://cdn.example.com';

      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(307, undefined, {
            Location: `${storageURL}/blob-data`,
          });

        // Storage returns 200 for blob existence
        nock(storageURL).head('/blob-data').reply(200);
      });

      it('follows the redirect and treats terminal 200 as exists', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCTET_STREAM);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('303 redirect on HEAD blob check preserves HEAD method', () => {
      const storageURL = 'https://cdn.example.com';

      beforeEach(() => {
        // Registry returns 303 for the HEAD blob check
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(303, undefined, {
            Location: `${storageURL}/blob-data`,
          });

        // Per Fetch spec, HEAD must remain HEAD on 303 (not become GET).
        // nock .head() only matches HEAD requests — if the redirect handler
        // incorrectly changes method to GET, this will not match and the
        // test will fail.
        nock(storageURL).head('/blob-data').reply(200);
      });

      it('keeps HEAD method after 303 redirect without downloading body', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCTET_STREAM);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('when HEAD blob check redirects to 404', () => {
      const storageURL = 'https://cdn.example.com';

      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(307, undefined, {
            Location: `${storageURL}/blob-data`,
          });

        nock(storageURL).head('/blob-data').reply(404);

        // Blob does not exist, so upload should proceed
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `/v2/${repoName}/blobs/uploads/123`,
          })
          .put(`/v2/${repoName}/blobs/uploads/123?digest=${digest}`)
          .reply(201);
      });

      it('treats terminal 404 as not-exists and uploads', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('cross-origin HEAD redirect does not receive registry credentials', () => {
      const storageURL = 'https://cdn.example.com';
      let authSubject: RegistryClient;
      let headInterceptor: nock.Interceptor;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        // Sign in to set up auth headers
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(307, undefined, {
            Location: `${storageURL}/blob-data`,
          });

        // Cross-origin target must NOT receive Authorization or custom headers
        headInterceptor = nock(storageURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        }).head('/blob-data');
        headInterceptor.reply(200);
      });

      it('strips Authorization and custom headers on cross-origin redirect', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('same-origin HEAD redirect retains registry credentials', () => {
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        // Same-origin redirect should retain credentials
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(307, undefined, {
            Location: `${registryURL}/internal/blob-check`,
          });

        nock(registryURL, {
          reqheaders: {
            authorization: /Basic/,
            'x-docker-custom': 'secret-value',
          },
        })
          .head('/internal/blob-check')
          .reply(200);
      });

      it('retains Authorization and custom headers on same-origin redirect', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('when upload-init POST redirects (307)', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(307, undefined, {
            Location: `${registryURL}/v2/${repoName}/blobs/uploads/redirected`,
          });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/redirected`)
          .reply(202, undefined, {
            Location: `/v2/${repoName}/blobs/uploads/session-456`,
          });

        nock(registryURL)
          .put(`/v2/${repoName}/blobs/uploads/session-456?digest=${digest}`)
          .reply(201);
      });

      it('follows the POST redirect and completes the upload', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('when upload-init POST redirects cross-origin', () => {
      const externalURL = 'https://uploads.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(307, undefined, {
            Location: `${externalURL}/upload-init`,
          });

        // Cross-origin redirect must NOT receive registry credentials
        nock(externalURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        })
          .post('/upload-init')
          .reply(202, undefined, {
            Location: `${externalURL}/upload/session-789`,
          });

        // Upload PUT to cross-origin location
        nock(externalURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        })
          .put(/\/upload\/session-789/)
          .reply(201);
      });

      it('follows cross-origin POST redirect without registry credentials', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('when upload Location is cross-origin (object storage)', () => {
      const storageURL = 'https://storage.cloud.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `${storageURL}/upload/abc`,
          });

        // Cross-origin PUT must NOT receive registry credentials
        nock(storageURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        })
          .put(`/upload/abc?digest=${digest}`)
          .reply(201);
      });

      it('uploads to cross-origin without registry credentials', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('when PUT upload redirects cross-origin', () => {
      const storageURL = 'https://blob-storage.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `${registryURL}/v2/${repoName}/blobs/uploads/456`,
          })
          .put(`/v2/${repoName}/blobs/uploads/456?digest=${digest}`)
          .reply(307, undefined, {
            Location: `${storageURL}/finalize-upload`,
          });

        // Cross-origin redirect target must NOT receive credentials
        nock(storageURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        })
          .put('/finalize-upload')
          .reply(201);
      });

      it('follows cross-origin PUT redirect without registry credentials', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('cross-origin blob PUT redirect retains Content-Type but strips Authorization', () => {
      const storageURL = 'https://presigned-storage.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `${registryURL}/v2/${repoName}/blobs/uploads/789`,
          })
          .put(`/v2/${repoName}/blobs/uploads/789?digest=${digest}`)
          .reply(307, undefined, {
            Location: `${storageURL}/upload-blob`,
          });

        // Cross-origin target MUST receive Content-Type (safe header for
        // pre-signed URL validity) but NOT Authorization or Docker headers
        nock(storageURL, {
          badheaders: ['authorization', 'x-docker-custom'],
          reqheaders: {
            'content-type': CONTENT_TYPE_OCTET_STREAM,
          },
        })
          .put('/upload-blob')
          .reply(201);
      });

      it('retains Content-Type on cross-origin redirect while stripping credentials', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('cross-origin blob Location retains Content-Type but not registry credentials', () => {
      const storageURL = 'https://object-storage.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            // Location points directly to cross-origin storage
            Location: `${storageURL}/upload/xyz`,
          });

        // Cross-origin PUT Location must receive Content-Type but NOT
        // registry Authorization or Docker HttpHeaders
        nock(storageURL, {
          badheaders: ['authorization', 'x-docker-custom'],
          reqheaders: {
            'content-type': CONTENT_TYPE_OCTET_STREAM,
          },
        })
          .put(`/upload/xyz?digest=${digest}`)
          .reply(201);
      });

      it('sends Content-Type to cross-origin Location without registry credentials', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
      });
    });

    describe('token Authorization is stripped on cross-origin redirect', () => {
      const storageURL = 'https://cdn-storage.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        const challenge =
          'Bearer realm="https://registry.example.com/token",service="svc",scope="repo:test:pull,push"';

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          })
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull,push' })
          .reply(200, { token: 'bearer-tok' });

        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'docker-val' },
        });

        // Blob upload: HEAD 404, POST 202 with same-origin location,
        // PUT redirects cross-origin
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `${registryURL}/v2/${repoName}/blobs/uploads/tok-upload`,
          })
          .put(`/v2/${repoName}/blobs/uploads/tok-upload?digest=${digest}`)
          .reply(307, undefined, {
            Location: `${storageURL}/finalize`,
          });

        // Cross-origin must NOT see the Bearer token or Docker headers,
        // but MUST see Content-Type
        nock(storageURL, {
          badheaders: ['authorization', 'x-docker-custom'],
          reqheaders: {
            'content-type': CONTENT_TYPE_OCTET_STREAM,
          },
        })
          .put('/finalize')
          .reply(201);
      });

      it('strips Bearer Authorization on cross-origin but retains Content-Type', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('registry -> cross-origin -> registry redirect chain never restores credentials', () => {
      const cdnURL = 'https://cdn.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        // HEAD blob check: registry -> CDN -> back to registry
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(307, undefined, {
            Location: `${cdnURL}/blob-check`,
          });

        // CDN must not receive credentials
        nock(cdnURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        })
          .head('/blob-check')
          .reply(307, undefined, {
            Location: `${registryURL}/internal/final-check`,
          });

        // Final registry hop must NOT receive credentials — once the chain
        // left the origin, defaults are permanently suppressed
        nock(registryURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        })
          .head('/internal/final-check')
          .reply(200);
      });

      it('does not reattach Authorization or Docker headers on return to registry', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('scheme change (https→http) strips registry credentials', () => {
      const httpURL = 'http://registry.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        // HEAD blob check redirects to same host but different scheme
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(307, undefined, {
            Location: `${httpURL}/blob-data`,
          });

        // Different scheme = different origin — must NOT receive credentials
        nock(httpURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        })
          .head('/blob-data')
          .reply(200);
      });

      it('strips credentials when scheme changes', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('port change strips registry credentials', () => {
      const portURL = 'https://registry.example.com:8443';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate':
              'Basic realm="registry.example.com" service="svc" scope="repo"',
          });
        await authSubject.signIn({
          username: 'user',
          password: 'pass',
          headers: { 'X-Docker-Custom': 'secret-value' },
        });

        // HEAD blob check redirects to same host but different port
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(307, undefined, {
            Location: `${portURL}/blob-data`,
          });

        // Different port = different origin — must NOT receive credentials
        nock(portURL, {
          badheaders: ['authorization', 'x-docker-custom'],
        })
          .head('/blob-data')
          .reply(200);
      });

      it('strips credentials when port changes', async () => {
        const response = await authSubject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('auth-realm redirect strips explicit Authorization cross-origin', () => {
      const authRealmURL = 'https://auth.example.com';
      const redirectTarget = 'https://auth2.example.com';
      let authSubject: RegistryClient;

      beforeEach(async () => {
        authSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });

        const challenge = `Bearer realm="${authRealmURL}/token",service="svc",scope="repo:test:pull"`;

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });

        // Auth realm redirects cross-origin — explicit Authorization stripped
        nock(authRealmURL)
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull' })
          .reply(302, undefined, {
            Location: `${redirectTarget}/token-final`,
          });

        nock(redirectTarget, {
          badheaders: ['authorization'],
        })
          .get('/token-final')
          .reply(200, { token: 'redirected-tok' });

        await authSubject.signIn({
          username: 'user',
          password: 'pass',
        });
      });

      it('strips Authorization on cross-origin auth-realm redirect', async () => {
        // If signIn succeeded, the token exchange completed correctly
        // and Authorization was stripped on the cross-origin hop
        expect(true).toBe(true);
      });
    });

    describe('when the upload location is missing', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202);
      });

      it('throws an error', async () => {
        await expect(subject.uploadBlob(blob)).rejects.toThrow(
          /missing location/i
        );
      });
    });

    describe('when the upload returns an unexpected status code', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `/v2/${repoName}/blobs/uploads/123`,
          })
          .put(`/v2/${repoName}/blobs/uploads/123?digest=${digest}`)
          .reply(203);
      });

      it('throws an error', async () => {
        await expect(subject.uploadBlob(blob)).rejects.toThrow(/expected 201/);
      });
    });

    describe('when the upload returns an unexpected status code but succeeds on retry', () => {
      let scope: nock.Scope;
      beforeEach(() => {
        scope = nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(500)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(200, undefined, {
            'Content-Length': blob.length.toString(),
          });
      });

      it('returns the blob digest', async () => {
        const subject = new RegistryClient(registryName, repoName, {
          retry: { retries: 1, minTimeout: 0, factor: 0 },
        });
        const response = await subject.uploadBlob(blob);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCTET_STREAM);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(blob.length);
        expect(scope.isDone()).toBe(true);
      });
    });
  });

  describe('checkManifest', () => {
    const reference = 'latest';
    const size = 123;
    const digest = 'sha256:deafbeef';

    describe('when the manifest exists', () => {
      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/manifests/${reference}`)
          .matchHeader(
            HEADER_ACCEPT,
            [
              CONTENT_TYPE_OCI_INDEX,
              CONTENT_TYPE_OCI_MANIFEST,
              CONTENT_TYPE_DOCKER_MANIFEST,
              CONTENT_TYPE_DOCKER_MANIFEST_LIST,
            ].join(',')
          )
          .reply(200, undefined, {
            [HEADER_CONTENT_TYPE]: CONTENT_TYPE_OCI_MANIFEST,
            [HEADER_DIGEST]: digest,
            [HEADER_CONTENT_LENGTH]: size.toString(),
          });
      });

      it('returns the manifest metadata', async () => {
        const response = await subject.checkManifest(reference);

        expect(response.mediaType).toEqual(CONTENT_TYPE_OCI_MANIFEST);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(size);
      });
    });
  });

  describe('getManifest', () => {
    describe('when the manifest exists', () => {
      const manifest = { foo: 'bar' };

      beforeEach(() => {
        nock(registryURL)
          .get(`/v2/${repoName}/manifests/latest`)
          .matchHeader(
            HEADER_ACCEPT,
            [
              CONTENT_TYPE_OCI_INDEX,
              CONTENT_TYPE_OCI_MANIFEST,
              CONTENT_TYPE_DOCKER_MANIFEST,
              CONTENT_TYPE_DOCKER_MANIFEST_LIST,
            ].join(',')
          )
          .reply(200, manifest, {
            [HEADER_CONTENT_TYPE]: 'application/json',
          });
      });

      it('returns the manifest', async () => {
        const response = await subject.getManifest('latest');
        expect(response.body).toEqual(manifest);
        expect(response.mediaType).toEqual('application/json');
      });
    });

    describe('when the manifest does not exist', () => {
      beforeEach(() => {
        nock(registryURL).get(`/v2/${repoName}/manifests/latest`).reply(404);
      });

      it('throws an error', async () => {
        expect.assertions(2);
        try {
          await subject.getManifest('latest');
        } catch (error) {
          assert(error instanceof HTTPError);
          expect(error.statusCode).toEqual(404);
          expect(error.message).toMatch(/expected 200/i);
        }
      });
    });
  });

  describe('uploadManifest', () => {
    const manifest = JSON.stringify({ foo: 'bar' });
    const digest = `sha256:${crypto
      .createHash('sha256')
      .update(manifest)
      .digest('hex')}`;

    describe('when uploading by digest', () => {
      beforeEach(() => {
        nock(registryURL)
          .put(`/v2/${repoName}/manifests/${digest}`)
          .matchHeader(HEADER_CONTENT_TYPE, CONTENT_TYPE_OCI_MANIFEST)
          .reply(201);
      });

      it('uploads the manifest', async () => {
        const response = await subject.uploadManifest(manifest);
        expect(response.mediaType).toEqual(CONTENT_TYPE_OCI_MANIFEST);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(manifest.length);
      });
    });

    describe('when uploading by reference', () => {
      const reference = 'latest';
      const contentType = 'application/json';

      beforeEach(() => {
        nock(registryURL)
          .put(`/v2/${repoName}/manifests/${reference}`)
          .matchHeader(HEADER_CONTENT_TYPE, contentType)
          .matchHeader(HEADER_IF_MATCH, '123')
          .reply(201);
      });

      it('uploads the manifest', async () => {
        const response = await subject.uploadManifest(manifest, {
          reference,
          mediaType: contentType,
          etag: '123',
        });
        expect(response.mediaType).toEqual(contentType);
        expect(response.digest).toEqual(digest);
        expect(response.size).toEqual(manifest.length);
      });
    });

    describe('when the upload returns an unexpected status code', () => {
      beforeEach(() => {
        nock(registryURL).put(`/v2/${repoName}/manifests/${digest}`).reply(203);
      });

      it('throws an error', async () => {
        await expect(subject.uploadManifest(manifest)).rejects.toThrow(
          /expected 201/
        );
      });
    });
  });

  describe('#securedFetch redirect handling', () => {
    describe('redirect limit at boundary (exactly 20 redirects succeeds)', () => {
      let scope: nock.Scope;

      beforeEach(() => {
        scope = nock(registryURL);

        // First request redirects: /v2/ → redirect-0 (1st redirect)
        scope.get('/v2/').reply(302, undefined, {
          Location: `${registryURL}/v2/redirect-0`,
        });

        // Redirects 2–20: redirect-0 → redirect-1 → … → redirect-18
        for (let i = 0; i < 19; i++) {
          scope.get(`/v2/redirect-${i}`).reply(302, undefined, {
            Location: `${registryURL}/v2/redirect-${i + 1}`,
          });
        }

        // Terminal (non-redirect) response at redirect-19 (21st request total)
        scope.get('/v2/redirect-19').reply(200, undefined, {
          [HEADER_API_VERSION]: 'registry/2.0',
        });
      });

      it('follows exactly 20 redirects and returns the terminal response', async () => {
        const version = await subject.checkVersion();
        expect(version).toEqual('registry/2.0');
        expect(scope.isDone()).toBe(true);
      });
    });

    describe('redirect limit exceeded (21st redirect throws)', () => {
      let scope: nock.Scope;

      beforeEach(() => {
        scope = nock(registryURL);

        // /v2/ → redirect-0 (1st redirect, i=0 in loop)
        scope.get('/v2/').reply(302, undefined, {
          Location: `${registryURL}/v2/redirect-0`,
        });

        // redirect-0 → … → redirect-19 (redirects 2–20, i=1..19)
        for (let i = 0; i < 19; i++) {
          scope.get(`/v2/redirect-${i}`).reply(302, undefined, {
            Location: `${registryURL}/v2/redirect-${i + 1}`,
          });
        }

        // redirect-19 is the 21st fetch (i=20): another redirect triggers limit
        scope.get('/v2/redirect-19').reply(302, undefined, {
          Location: `${registryURL}/v2/redirect-20`,
        });
      });

      it('throws a max-redirect error after exactly 21 requests', async () => {
        await expect(subject.checkVersion()).rejects.toThrow(
          /maximum redirect reached/
        );
        // All 21 interceptors consumed — none left over
        expect(scope.isDone()).toBe(true);
        // The would-be next hop was never fetched
        expect(scope.pendingMocks()).toHaveLength(0);
      });
    });

    describe('redirect without Location header', () => {
      beforeEach(() => {
        nock(registryURL).get('/v2/').reply(302, undefined, {});
      });

      it('throws a missing location error', async () => {
        await expect(subject.checkVersion()).rejects.toThrow(
          /redirect location header missing/
        );
      });
    });

    describe('303 redirect converts POST to GET and strips entity headers', () => {
      const blob = Buffer.from('test-303', 'utf8');
      const digest = `sha256:${crypto
        .createHash('sha256')
        .update(blob)
        .digest('hex')}`;

      beforeEach(() => {
        nock(registryURL)
          .head(`/v2/${repoName}/blobs/${digest}`)
          .reply(404);

        // POST to initiate upload gets a 303 See Other → must become GET
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(303, undefined, {
            Location: `${registryURL}/v2/${repoName}/blobs/uploads/see-other`,
          });

        // The redirected request MUST be GET without Content-Type (entity
        // header removed) — nock .get() ensures method changed from POST.
        nock(registryURL, {
          badheaders: ['content-type', 'content-length'],
        })
          .get(`/v2/${repoName}/blobs/uploads/see-other`)
          .reply(202, undefined, {
            Location: `/v2/${repoName}/blobs/uploads/final`,
          });

        nock(registryURL)
          .put(`/v2/${repoName}/blobs/uploads/final?digest=${digest}`)
          .reply(201);
      });

      it('converts POST to GET on 303 and removes entity headers', async () => {
        const response = await subject.uploadBlob(blob);
        expect(response.digest).toEqual(digest);
      });
    });

    describe('301/302 redirect converts POST to GET', () => {
      it.each([301, 302])(
        '%d redirect on POST converts to GET without body',
        async (status) => {
          const blob = Buffer.from(`test-${status}`, 'utf8');
          const digest = `sha256:${crypto
            .createHash('sha256')
            .update(blob)
            .digest('hex')}`;

          nock(registryURL)
            .head(`/v2/${repoName}/blobs/${digest}`)
            .reply(404);

          // POST gets redirected with 301/302 → must become GET
          nock(registryURL)
            .post(`/v2/${repoName}/blobs/uploads/`)
            .reply(status, undefined, {
              Location: `${registryURL}/v2/${repoName}/blobs/uploads/moved`,
            });

          // Must be GET, no entity headers
          nock(registryURL, {
            badheaders: ['content-type', 'content-length'],
          })
            .get(`/v2/${repoName}/blobs/uploads/moved`)
            .reply(202, undefined, {
              Location: `/v2/${repoName}/blobs/uploads/session-x`,
            });

          nock(registryURL)
            .put(`/v2/${repoName}/blobs/uploads/session-x?digest=${digest}`)
            .reply(201);

          const response = await subject.uploadBlob(blob);
          expect(response.digest).toEqual(digest);
        }
      );
    });

    describe('stripEntityHeaders retains safe headers', () => {
      const manifest = JSON.stringify({ test: 'entity-headers' });
      const mDigest = `sha256:${crypto
        .createHash('sha256')
        .update(manifest)
        .digest('hex')}`;

      beforeEach(() => {
        // uploadManifest with etag carries both Content-Type (entity) and
        // If-Match (safe). A 303 converts PUT→GET, stripEntityHeaders must
        // remove Content-Type but retain If-Match.
        nock(registryURL)
          .put(`/v2/${repoName}/manifests/${mDigest}`)
          .reply(303, undefined, {
            Location: `${registryURL}/v2/${repoName}/manifests/redirect-target`,
          });

        // The redirected GET must NOT have content-type but MUST have if-match
        nock(registryURL, {
          badheaders: ['content-type'],
          reqheaders: { 'if-match': 'etag-123' },
        })
          .get(`/v2/${repoName}/manifests/redirect-target`)
          .reply(201);
      });

      it('removes entity headers but retains safe headers after method change', async () => {
        const response = await subject.uploadManifest(manifest, {
          etag: 'etag-123',
        });
        expect(response.digest).toEqual(mDigest);
      });
    });
  });

  describe('#tokenFetch redirect handling', () => {
    describe('redirect limit at boundary (exactly 20 redirects succeeds) in token exchange', () => {
      const challenge =
        `Bearer realm="https://registry.example.com/token",service="svc",scope="repo:test:pull"`;

      let scope: nock.Scope;

      beforeEach(() => {
        scope = nock(registryURL);

        // POST triggers a 401 → token exchange
        scope
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });

        // Token endpoint: /token → token-redirect-0 (1st redirect, i=0)
        scope
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull' })
          .reply(302, undefined, {
            Location: `${registryURL}/token-redirect-0`,
          });

        // Redirects 2–20: token-redirect-0 → … → token-redirect-18
        for (let i = 0; i < 19; i++) {
          scope.get(`/token-redirect-${i}`).reply(302, undefined, {
            Location: `${registryURL}/token-redirect-${i + 1}`,
          });
        }

        // Terminal response at token-redirect-19 (21st request in tokenFetch)
        scope
          .get('/token-redirect-19')
          .reply(200, { token: 'boundary-token' });


      });

      it('follows exactly 20 redirects in token exchange and succeeds', async () => {
        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });
        await tokenSubject.signIn({ username: 'user', password: 'pass' });
        expect(scope.isDone()).toBe(true);
      });
    });

    describe('redirect limit exceeded (21st redirect throws) in token exchange', () => {
      const challenge =
        `Bearer realm="https://registry.example.com/token",service="svc",scope="repo:test:pull"`;

      let scope: nock.Scope;

      beforeEach(() => {
        scope = nock(registryURL);

        // POST triggers a 401 → token exchange
        scope
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });

        // Token endpoint: /token → token-redirect-0 (1st redirect, i=0)
        scope
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull' })
          .reply(302, undefined, {
            Location: `${registryURL}/token-redirect-0`,
          });

        // Redirects 2–20: token-redirect-0 → … → token-redirect-18 (i=1..19)
        for (let i = 0; i < 19; i++) {
          scope.get(`/token-redirect-${i}`).reply(302, undefined, {
            Location: `${registryURL}/token-redirect-${i + 1}`,
          });
        }

        // token-redirect-19 is the 21st fetch (i=20): one more redirect → limit
        scope.get('/token-redirect-19').reply(302, undefined, {
          Location: `${registryURL}/token-redirect-20`,
        });
      });

      it('throws a max-redirect error after exactly 21 requests in tokenFetch', async () => {
        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });
        await expect(
          tokenSubject.signIn({ username: 'user', password: 'pass' })
        ).rejects.toThrow(/maximum redirect reached/);
        // All interceptors consumed — no unused mocks
        expect(scope.isDone()).toBe(true);
        expect(scope.pendingMocks()).toHaveLength(0);
      });
    });

    describe('redirect without Location in token exchange', () => {
      const challenge =
        `Bearer realm="https://registry.example.com/token",service="svc",scope="repo:test:pull"`;

      beforeEach(() => {
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });

        // Token endpoint redirects without a Location header
        nock(registryURL)
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull' })
          .reply(302, undefined, {});
      });

      it('throws a missing location error', async () => {
        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });
        await expect(
          tokenSubject.signIn({ username: 'user', password: 'pass' })
        ).rejects.toThrow(/redirect location header missing/);
      });
    });

    describe('303 on distribution token GET preserves GET method', () => {
      const challenge =
        `Bearer realm="https://registry.example.com/token",service="svc",scope="repo:test:pull"`;

      beforeEach(() => {
        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': challenge,
          });

        // Token GET receives 303 → method stays GET (already GET)
        nock(registryURL)
          .get('/token')
          .query({ service: 'svc', scope: 'repo:test:pull' })
          .reply(303, undefined, {
            Location: `${registryURL}/token-see-other`,
          });

        // Remains GET after 303 (method !== 'GET' check is false)
        nock(registryURL)
          .get('/token-see-other')
          .reply(200, { token: 'tok-303-get' });
      });

      it('does not change method when already GET on 303', async () => {
        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });
        await expect(
          tokenSubject.signIn({ username: 'user', password: 'pass' })
        ).resolves.toBeUndefined();
      });
    });

    describe('OAuth token POST redirect handling', () => {
      it('303 on OAuth POST converts to GET and strips entity headers', async () => {
        const oauthChallenge =
          `Bearer realm="https://registry.example.com/oauth2/token",service="svc",scope="repo:test:pull"`;

        nock(registryURL)
          .post(`/v2/${repoName}/blobs/uploads/`)
          .reply(401, undefined, {
            'WWW-Authenticate': oauthChallenge,
          });

        // OAuth POST gets 303 → must become GET, entity headers removed
        nock(registryURL)
          .post('/oauth2/token')
          .reply(303, undefined, {
            Location: `${registryURL}/oauth2/token-get`,
          });

        // Must be GET, no content-type
        nock(registryURL, {
          badheaders: ['content-type', 'content-length'],
        })
          .get('/oauth2/token-get')
          .reply(200, { access_token: 'oauth-tok-303' });

        const tokenSubject = new RegistryClient(registryName, repoName, {
          retry: false,
        });
        await expect(
          tokenSubject.signIn({ username: '<token>', password: 'pass' })
        ).resolves.toBeUndefined();
      });

      it.each([301, 302])(
        '%d on OAuth POST converts to GET without body',
        async (status) => {
          const oauthChallenge =
            `Bearer realm="https://registry.example.com/oauth2/token",service="svc",scope="repo:test:pull"`;

          nock(registryURL)
            .post(`/v2/${repoName}/blobs/uploads/`)
            .reply(401, undefined, {
              'WWW-Authenticate': oauthChallenge,
            });

          // OAuth POST gets 301/302 → must become GET
          nock(registryURL)
            .post('/oauth2/token')
            .reply(status, undefined, {
              Location: `${registryURL}/oauth2/token-moved`,
            });

          // Must be GET, no entity headers
          nock(registryURL, {
            badheaders: ['content-type', 'content-length'],
          })
            .get('/oauth2/token-moved')
            .reply(200, { access_token: `oauth-tok-${status}` });

          const tokenSubject = new RegistryClient(registryName, repoName, {
            retry: false,
          });
          await expect(
            tokenSubject.signIn({ username: '<token>', password: 'pass' })
          ).resolves.toBeUndefined();
        }
      );
    });
  });
});
