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
import crypto from 'node:crypto';
import {
  CONTENT_TYPE_OCI_INDEX,
  CONTENT_TYPE_OCI_MANIFEST,
  CONTENT_TYPE_OCTET_STREAM,
  HEADER_AUTHENTICATE,
  HEADER_CONTENT_TYPE,
  HEADER_DIGEST,
  HEADER_OCI_SUBJECT,
} from '../constants';
import { Credentials } from '../credentials';
import { OCIImage } from '../image';
import { ImageName } from '../name';
import { ZERO_DIGEST } from '../registry';
import { ImageIndex } from '../types';

describe('OCIImage', () => {
  const imageName: ImageName = {
    registry: 'registry',
    path: 'path',
  };

  const headers = { 'X-Custom-Auth': 'authtoken' };
  const creds: Credentials = {
    username: 'username',
    password: 'password',
    headers,
  };

  describe('constructor', () => {
    it('should construct', () => {
      const image = new OCIImage(imageName, creds);
      expect(image).toBeDefined();
    });
  });

  describe('#addArtifact', () => {
    const subject = new OCIImage(imageName, creds, { retry: false });
    const registry = imageName.registry;
    const repo = imageName.path;

    const artifact = Buffer.from('artifact');
    const mediaType = 'mediaType';
    const imageDigest = 'sha256:deadbeef';
    const annotations = { annotation: 'value' };

    const challenge = 'Basic realm="registry"';
    const artifactDigest = `sha256:${crypto
      .createHash('sha256')
      .update(artifact)
      .digest('hex')}`;
    const emptyDigest = `sha256:${crypto
      .createHash('sha256')
      .update(Buffer.from('{}'))
      .digest('hex')}`;
    const artifactManifestDigest = 'sha256:cafed00d';

    describe('when the registry supports referrers', () => {
      beforeEach(() => {
        nock(`https://${registry}`, { reqheaders: headers })
          .post(`/v2/${repo}/blobs/uploads/`)
          .reply(401, {}, { [HEADER_AUTHENTICATE]: challenge })
          .head(`/v2/${repo}/manifests/${imageDigest}`)
          .reply(200, {})
          .head(`/v2/${repo}/blobs/${artifactDigest}`)
          .reply(404, {})
          .head(`/v2/${repo}/blobs/${emptyDigest}`)
          .reply(200, {})
          .post(`/v2/${repo}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `/v2/${repo}/blobs/uploads/123`,
          })
          .put(`/v2/${repo}/blobs/uploads/123?digest=${artifactDigest}`)
          .matchHeader(HEADER_CONTENT_TYPE, CONTENT_TYPE_OCTET_STREAM)
          .reply(201);

        nock(`https://${registry}`, { reqheaders: headers })
          .filteringPath(/sha256:[0-9a-f]{64}/, artifactManifestDigest)
          .put(`/v2/${repo}/manifests/${artifactManifestDigest}`)
          .reply(201, undefined, {
            [HEADER_OCI_SUBJECT]: artifactManifestDigest,
          });

        nock(`https://${registry}`, { reqheaders: headers })
          .get(`/v2/${repo}/referrers/${ZERO_DIGEST}`)
          .reply(200);
      });

      it('adds an artifact', async () => {
        const descriptor = await subject.addArtifact({
          artifact,
          mediaType,
          imageDigest,
          annotations,
        });

        expect(descriptor.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(descriptor.mediaType).toBe(CONTENT_TYPE_OCI_MANIFEST);
        expect(descriptor.size).toBeGreaterThan(0);
      });
    });

    describe('when the registry does NOT support referrers', () => {
      beforeEach(() => {
        nock(`https://${registry}`, { reqheaders: headers })
          .post(`/v2/${repo}/blobs/uploads/`)
          .reply(401, {}, { [HEADER_AUTHENTICATE]: challenge })
          .head(`/v2/${repo}/manifests/${imageDigest}`)
          .reply(200, {})
          .head(`/v2/${repo}/blobs/${artifactDigest}`)
          .reply(404, {})
          .head(`/v2/${repo}/blobs/${emptyDigest}`)
          .reply(200, {})
          .post(`/v2/${repo}/blobs/uploads/`)
          .reply(202, undefined, {
            Location: `/v2/${repo}/blobs/uploads/123`,
          })
          .put(`/v2/${repo}/blobs/uploads/123?digest=${artifactDigest}`)
          .matchHeader(HEADER_CONTENT_TYPE, CONTENT_TYPE_OCTET_STREAM)
          .reply(201)
          .get(`/v2/${repo}/referrers/${ZERO_DIGEST}`)
          .reply(404);

        nock(`https://${registry}`, { reqheaders: headers })
          .filteringPath(/sha256:[0-9a-f]{64}/, artifactManifestDigest)
          .put(`/v2/${repo}/manifests/${artifactManifestDigest}`)
          .reply(201, undefined);
      });

      describe('when there is NO existing referrer index', () => {
        beforeEach(() => {
          nock(`https://${registry}`, { reqheaders: headers })
            .get(`/v2/${repo}/manifests/sha256-deadbeef`)
            .reply(404, undefined)
            .put(`/v2/${repo}/manifests/sha256-deadbeef`)
            .reply(201, undefined);
        });

        it('adds an artifact', async () => {
          const descriptor = await subject.addArtifact({
            artifact,
            mediaType,
            imageDigest,
            annotations,
          });

          expect(descriptor.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
          expect(descriptor.mediaType).toBe(CONTENT_TYPE_OCI_MANIFEST);
          expect(descriptor.size).toBeGreaterThan(0);
        });
      });

      describe('when there is an existing referrer index', () => {
        const index: ImageIndex = {
          mediaType: CONTENT_TYPE_OCI_INDEX,
          schemaVersion: 2,
          manifests: [
            {
              mediaType: CONTENT_TYPE_OCI_MANIFEST,
              digest: artifactManifestDigest,
              size: 0,
            },
          ],
        };

        beforeEach(() => {
          nock(`https://${registry}`, { reqheaders: headers })
            .get(`/v2/${repo}/manifests/sha256-deadbeef`)
            .reply(200, index, {
              [HEADER_CONTENT_TYPE]: CONTENT_TYPE_OCI_INDEX,
            })
            .put(`/v2/${repo}/manifests/sha256-deadbeef`)
            .reply(201, undefined);
        });

        it('adds an artifact', async () => {
          const descriptor = await subject.addArtifact({
            artifact,
            mediaType,
            imageDigest,
            annotations,
          });

          expect(descriptor.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
          expect(descriptor.mediaType).toBe(CONTENT_TYPE_OCI_MANIFEST);
          expect(descriptor.size).toBeGreaterThan(0);
        });
      });

      describe('when the referrer index is NOT the expected type', () => {
        beforeEach(() => {
          nock(`https://${registry}`, { reqheaders: headers })
            .get(`/v2/${repo}/manifests/sha256-deadbeef`)
            .reply(
              200,
              {},
              {
                [HEADER_CONTENT_TYPE]: 'text/plain',
              }
            );
        });

        it('throws an error', async () => {
          await expect(
            subject.addArtifact({
              artifact,
              mediaType,
              imageDigest,
              annotations,
            })
          ).rejects.toThrow(/error uploading artifact/i);
        });
      });

      describe('when there is an error retrieving the referrer index', () => {
        beforeEach(() => {
          nock(`https://${registry}`, { reqheaders: headers })
            .get(`/v2/${repo}/manifests/sha256-deadbeef`)
            .reply(418, undefined);
        });

        it('throws an error', async () => {
          await expect(
            subject.addArtifact({
              artifact,
              mediaType,
              imageDigest,
              annotations,
            })
          ).rejects.toThrow();
        });
      });
    });
  });

  describe('#getDigest', () => {
    const subject = new OCIImage(imageName, creds, { retry: false });
    const registry = imageName.registry;
    const repo = imageName.path;
    const tag = 'latest';
    const challenge = 'Basic realm="registry"';
    const imageDigest = 'sha256:deadbeef';

    describe('when the tag exists', () => {
      beforeEach(() => {
        nock(`https://${registry}`)
          .post(`/v2/${repo}/blobs/uploads/`)
          .reply(401, {}, { [HEADER_AUTHENTICATE]: challenge })
          .head(`/v2/${repo}/manifests/${tag}`)
          .reply(200, {}, { [HEADER_DIGEST]: imageDigest });
      });

      it('returns the digest for the tag', async () => {
        const response = await subject.getDigest(tag);

        expect(response).toEqual(imageDigest);
      });
    });

    describe('when the tag does NOT exist', () => {
      beforeEach(() => {
        nock(`https://${registry}`)
          .post(`/v2/${repo}/blobs/uploads/`)
          .reply(401, {}, { [HEADER_AUTHENTICATE]: challenge })
          .head(`/v2/${repo}/manifests/${tag}`)
          .reply(404, {});
      });

      it('throws an error', async () => {
        await expect(subject.getDigest(tag)).rejects.toThrow();
      });
    });

    describe('when the registry is docker', () => {
      let scope: nock.Scope;
      const registry = 'docker.io';
      const imageName: ImageName = {
        registry,
        path: 'path',
      };

      beforeEach(() => {
        scope = nock(`https://registry-1.docker.io`)
          .post(`/v2/${repo}/blobs/uploads/`)
          .reply(401, {}, { [HEADER_AUTHENTICATE]: challenge })
          .head(`/v2/${repo}/manifests/${tag}`)
          .reply(200, {}, { [HEADER_DIGEST]: imageDigest });
      });

      it('returns the digest for the tag (from registry1-docker.io)', async () => {
        const subject = new OCIImage(imageName, creds, { retry: false });
        const response = await subject.getDigest(tag);

        expect(response).toEqual(imageDigest);
        expect(scope.isDone()).toBe(true);
      });
    });
  });
});
