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
    const creds = { username: 'username', password: 'password' };

    describe('when the client is already signed in', () => {
      beforeEach(() => {
        nock(registryURL)
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

    describe('when the registry uses an bearer token returns an error', () => {
       
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
});
