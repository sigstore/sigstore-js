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
import { fromPartial } from '@total-typescript/shoehorn';
import nock from 'nock';
import crypto from 'node:crypto';
import {
  AttachArtifactOptions,
  Credentials,
  Descriptor,
  OCIError,
  attachArtifactToImage,
  getRegistryCredentials,
} from '..';
import { CONTENT_TYPE_OCI_MANIFEST, HEADER_OCI_SUBJECT } from '../constants';

describe('attachArtifactToImage', () => {
  const registry = 'my-registry';
  const repo = 'my-repo';
  const imageName = `${registry}/${repo}`;
  const imageDigest = 'sha256:deadbeef';
  const artifact = Buffer.from('artifact');
  const mediaType = 'mediaType';

  describe('when all calls are successful', () => {
    const username = 'username';
    const password = 'password';
    const credentials = { username, password };

    const artifactDigest = `sha256:${crypto
      .createHash('sha256')
      .update(artifact)
      .digest('hex')}`;
    const emptyDigest = `sha256:${crypto
      .createHash('sha256')
      .update(Buffer.from('{}'))
      .digest('hex')}`;
    const artifactManifestDigest = 'sha256:cafed00d';

    beforeEach(() => {
      nock(`https://${registry}`)
        .post(`/v2/${repo}/blobs/uploads/`)
        .reply(200, {});

      nock(`https://${registry}`)
        .head(`/v2/${repo}/manifests/${imageDigest}`)
        .reply(200, {});

      nock(`https://${registry}`)
        .head(`/v2/${repo}/blobs/${artifactDigest}`)
        .reply(200, {});

      nock(`https://${registry}`)
        .head(`/v2/${repo}/blobs/${emptyDigest}`)
        .reply(200, {});

      nock(`https://${registry}`)
        .filteringPath(/sha256:[0-9a-f]{64}/, artifactManifestDigest)
        .put(`/v2/${repo}/manifests/${artifactManifestDigest}`)
        .reply(201, undefined, {
          [HEADER_OCI_SUBJECT]: artifactManifestDigest,
        });
    });

    it('should return the artifact digest', async () => {
      const descriptor = await attachArtifactToImage({
        credentials,
        artifact,
        imageDigest,
        imageName,
        mediaType,
        fetchOpts: { retry: false },
      });

      expect(descriptor.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(descriptor.mediaType).toEqual(CONTENT_TYPE_OCI_MANIFEST);
    });
  });
});

describe('exports', () => {
  it('exports types', async () => {
    const attachArtifactOptions: AttachArtifactOptions = fromPartial({});
    expect(attachArtifactOptions).toBeDefined();

    const credentials: Credentials = fromPartial({});
    expect(credentials).toBeDefined();

    const descriptor: Descriptor = fromPartial({});
    expect(descriptor).toBeDefined();
  });

  it('exports classes', () => {
    expect(OCIError).toBeDefined();
  });

  it('exports functions', () => {
    expect(attachArtifactToImage).toBeDefined();
    expect(getRegistryCredentials).toBeDefined();
  });
});
