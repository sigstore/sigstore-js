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
export const CONTENT_TYPE_OCI_INDEX = 'application/vnd.oci.image.index.v1+json';
export const CONTENT_TYPE_OCI_MANIFEST =
  'application/vnd.oci.image.manifest.v1+json';
export const CONTENT_TYPE_DOCKER_MANIFEST =
  'application/vnd.docker.distribution.manifest.v2+json';
export const CONTENT_TYPE_DOCKER_MANIFEST_LIST =
  'application/vnd.docker.distribution.manifest.list.v2+json';
export const CONTENT_TYPE_OCTET_STREAM = 'application/octet-stream';
export const CONTENT_TYPE_EMPTY_DESCRIPTOR =
  'application/vnd.oci.empty.v1+json';

export const HEADER_ACCEPT = 'Accept';
export const HEADER_API_VERSION = 'Docker-Distribution-API-Version';
export const HEADER_AUTHENTICATE = 'WWW-Authenticate';
export const HEADER_AUTHORIZATION = 'Authorization';
export const HEADER_CONTENT_LENGTH = 'Content-Length';
export const HEADER_CONTENT_TYPE = 'Content-Type';
export const HEADER_DIGEST = 'Docker-Content-Digest';
export const HEADER_ETAG = 'Etag';
export const HEADER_IF_MATCH = 'If-Match';
export const HEADER_LOCATION = 'Location';
export const HEADER_OCI_SUBJECT = 'OCI-Subject';
