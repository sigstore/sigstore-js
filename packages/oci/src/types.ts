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

// https://github.com/opencontainers/image-spec/blob/main/descriptor.md#properties
export type Descriptor = {
  mediaType: string;
  digest: string;
  size: number;
  artifactType?: string;
  urls?: string[];
  annotations?: Record<string, string>;
  data?: string;
};

// https://github.com/opencontainers/image-spec/blob/main/manifest.md#image-manifest-property-descriptions
export type ImageManifest = {
  schemaVersion: number;
  mediaType: string;
  artifactType?: string;
  config: Descriptor;
  layers: Descriptor[];
  subject?: Descriptor;
  annotations?: Record<string, string>;
};

// https://github.com/opencontainers/image-spec/blob/main/image-index.md#image-index-property-descriptions
export type Platform = {
  architecture: string;
  os: string;
  'os.version'?: string;
  'os.features'?: string[];
  variant?: string;
  features?: string[];
};

export type ImageIndex = {
  schemaVersion: number;
  mediaType: string;
  artifactType?: string;
  manifests: (Descriptor & { platform?: Platform })[];
  subject?: Descriptor;
  annotations?: Record<string, string>;
};
