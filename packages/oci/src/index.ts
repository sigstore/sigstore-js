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
import { Credentials } from './credentials';
import { AddArtifactOptions, OCIImage } from './image';
import { parseImageName } from './name';

import type { RegistryFetchOptions as FetchOptions } from './registry';
import type { Descriptor } from './types';

export type { Credentials, Descriptor };

export type AttachArtifactOptions = AddArtifactOptions & {
  readonly imageName: string;
  readonly credentials: Credentials;
};

export type GetImageDigestOptions = {
  readonly imageName: string;
  readonly imageTag: string;
  readonly credentials: Credentials;
  readonly fetchOpts?: FetchOptions;
};

export { getRegistryCredentials } from './credentials';
export { OCIError } from './error';

// Associates the given artifact with an OCI image. The artifact is identified
// by its media type and a buffer containing the artifact. The image is
// identified by its FQDN and digest.
export const attachArtifactToImage = async (
  opts: AttachArtifactOptions
): Promise<Descriptor> => {
  const image = parseImageName(opts.imageName);
  return new OCIImage(image, opts.credentials, opts.fetchOpts).addArtifact(
    opts
  );
};

// Returns the digest of the given image tag in the remote registry.
export const getImageDigest = async (
  opts: GetImageDigestOptions
): Promise<string> => {
  const image = parseImageName(opts.imageName);
  return new OCIImage(image, opts.credentials, opts.fetchOpts).getDigest(
    opts.imageTag
  );
};
