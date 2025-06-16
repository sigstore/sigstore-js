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
import {
  CONTENT_TYPE_EMPTY_DESCRIPTOR,
  CONTENT_TYPE_OCI_INDEX,
  CONTENT_TYPE_OCI_MANIFEST,
} from './constants';
import { Credentials } from './credentials';
import { HTTPError, OCIError } from './error';
import { ImageName } from './name';
import {
  RegistryFetchOptions as FetchOptions,
  RegistryClient,
  UploadManifestResponse,
} from './registry';

import type { Descriptor, ImageIndex, ImageManifest } from './types';

const DOCKER_DEFAULT_REGISTRY = 'registry-1.docker.io';
const EMPTY_BLOB = Buffer.from('{}');

export type AddArtifactOptions = {
  readonly artifact: Buffer;
  readonly mediaType: string;
  readonly imageDigest: string;
  readonly annotations?: Record<string, string>;
  readonly fetchOpts?: FetchOptions;
};

export class OCIImage {
  readonly #client: RegistryClient;
  readonly #credentials: Credentials;

  constructor(image: ImageName, creds: Credentials, opts?: FetchOptions) {
    this.#client = new RegistryClient(
      canonicalizeRegistryName(image.registry),
      image.path,
      opts
    );
    this.#credentials = creds;
  }

  async addArtifact(opts: AddArtifactOptions): Promise<Descriptor> {
    let artifactDescriptor: UploadManifestResponse;

    const annotations = {
      'org.opencontainers.image.created': new Date().toISOString(),
      ...opts.annotations,
    };

    try {
      /* istanbul ignore else */
      if (this.#credentials) {
        await this.#client.signIn(this.#credentials);
      }

      // Check that the image exists
      const imageDescriptor = await this.#client.checkManifest(
        opts.imageDigest
      );

      // Upload the artifact blob
      const artifactBlob = await this.#client.uploadBlob(opts.artifact);

      // Upload the empty blob (needed for the manifest config)
      const emptyBlob = await this.#client.uploadBlob(EMPTY_BLOB);

      // Construct artifact manifest
      const manifest = buildManifest({
        artifactDescriptor: { ...artifactBlob, mediaType: opts.mediaType },
        subjectDescriptor: imageDescriptor,
        configDescriptor: {
          ...emptyBlob,
          mediaType: CONTENT_TYPE_EMPTY_DESCRIPTOR,
        },
        annotations,
      });

      // Upload artifact manifest
      artifactDescriptor = await this.#client.uploadManifest(
        JSON.stringify(manifest)
      );

      // Check to see if registry supports the referrers API. For most
      // registries the presence of a subjectDigest response header when
      // uploading the artifact manifest indicates that the referrers API IS
      // supported -- however, this is not a guarantee (AWS ECR does NOT support
      // the referrers API but still reports a subjectDigest).
      const referrersSupported = await this.#client.pingReferrers();

      // Manually update the referrers list if the referrers API is not supported.
      if (!artifactDescriptor.subjectDigest || !referrersSupported) {
        // Strip subjectDigest from the artifact descriptor (in case it was returned)
        /* eslint-disable-next-line @typescript-eslint/no-unused-vars */
        const { subjectDigest, ...descriptor } = artifactDescriptor;

        await this.#createReferrersIndexByTag({
          artifact: {
            ...descriptor,
            artifactType: opts.mediaType,
            annotations,
          },
          imageDigest: opts.imageDigest,
        });
      }
    } catch (err) {
      throw new OCIError({
        message: `Error uploading artifact to container registry`,
        cause: err,
      });
    }

    return artifactDescriptor;
  }

  async getDigest(tag: string): Promise<string> {
    try {
      /* istanbul ignore else */
      if (this.#credentials) {
        await this.#client.signIn(this.#credentials);
      }

      const imageDescriptor = await this.#client.checkManifest(tag);
      return imageDescriptor.digest;
    } catch (err) {
      throw new OCIError({
        message: `Error retrieving image digest from container registry`,
        cause: err,
      });
    }
  }

  // Create a referrers index by tag. This is a fallback for registries that do
  // not support the referrers API.
  // https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pushing-manifests-with-subject
  async #createReferrersIndexByTag(opts: {
    artifact: Descriptor;
    imageDigest: string;
  }): Promise<void> {
    const referrerTag = digestToTag(opts.imageDigest);
    let referrerManifest: ImageIndex;
    let etag: string | undefined;

    try {
      // Retrieve any existing referrer index
      const referrerIndex = await this.#client.getManifest(referrerTag);

      if (referrerIndex.mediaType !== CONTENT_TYPE_OCI_INDEX) {
        throw new Error(
          `Expected referrer manifest type ${CONTENT_TYPE_OCI_INDEX}, got ${referrerIndex.mediaType}`
        );
      }

      referrerManifest = referrerIndex.body as ImageIndex;
      etag = referrerIndex.etag;
    } catch (err) {
      // If the referrer index does not exist, create a new one
      if (err instanceof HTTPError && err.statusCode === 404) {
        referrerManifest = newIndex();
      } else {
        throw err;
      }
    }

    // If the artifact is not already in the index, add it to the list and
    // re-upload the index
    /* istanbul ignore else */
    if (
      !referrerManifest.manifests.some(
        (manifest) => manifest.digest === opts.artifact.digest
      )
    ) {
      // Add the artifact to the index
      referrerManifest.manifests.push(opts.artifact);

      await this.#client.uploadManifest(JSON.stringify(referrerManifest), {
        mediaType: CONTENT_TYPE_OCI_INDEX,
        reference: referrerTag,
        etag,
      });
    }
  }
}

// Build an OCI manifest document with references to the given artifact,
// subject, and config
const buildManifest = (opts: {
  artifactDescriptor: Descriptor;
  subjectDescriptor: Descriptor;
  configDescriptor: Descriptor;
  annotations?: Record<string, string>;
}): ImageManifest => ({
  schemaVersion: 2,
  mediaType: CONTENT_TYPE_OCI_MANIFEST,
  artifactType: opts.artifactDescriptor.mediaType,
  config: opts.configDescriptor,
  layers: [opts.artifactDescriptor],
  subject: opts.subjectDescriptor,
  annotations: opts.annotations,
});

// Return an empty OCI index document
const newIndex = (): ImageIndex => ({
  mediaType: CONTENT_TYPE_OCI_INDEX,
  schemaVersion: 2,
  manifests: [],
});

// Convert an image digest to a tag per the Referrers Tag Schema
// https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema
const digestToTag = (digest: string): string => {
  return digest.replace(':', '-');
};

// Canonicalize the registry name to match the format used by the registry
// client. This is used primarily to handle the special case of the Docker Hub
// registry.
// https://github.com/moby/moby/blob/v24.0.2/registry/config.go#L25-L48
const canonicalizeRegistryName = (registry: string): string => {
  return registry.endsWith('docker.io') ? DOCKER_DEFAULT_REGISTRY : registry;
};
