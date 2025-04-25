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
import crypto from 'node:crypto';
import {
  CONTENT_TYPE_DOCKER_MANIFEST,
  CONTENT_TYPE_DOCKER_MANIFEST_LIST,
  CONTENT_TYPE_OCI_INDEX,
  CONTENT_TYPE_OCI_MANIFEST,
  CONTENT_TYPE_OCTET_STREAM,
  HEADER_ACCEPT,
  HEADER_API_VERSION,
  HEADER_AUTHENTICATE,
  HEADER_AUTHORIZATION,
  HEADER_CONTENT_LENGTH,
  HEADER_CONTENT_TYPE,
  HEADER_DIGEST,
  HEADER_ETAG,
  HEADER_IF_MATCH,
  HEADER_LOCATION,
  HEADER_OCI_SUBJECT,
} from './constants';
import { Credentials, toBasicAuth } from './credentials';
import { ensureStatus } from './error';
import fetch, { FetchInterface, FetchOptions } from './fetch';

import type { Descriptor } from './types';

const ALL_MANIFEST_MEDIA_TYPES = [
  CONTENT_TYPE_OCI_INDEX,
  CONTENT_TYPE_OCI_MANIFEST,
  CONTENT_TYPE_DOCKER_MANIFEST,
  CONTENT_TYPE_DOCKER_MANIFEST_LIST,
].join(',');

export const ZERO_DIGEST =
  'sha256:0000000000000000000000000000000000000000000000000000000000000000';

export type UploadBlobResponse = Descriptor;

export type UploadManifestOptions = {
  readonly reference?: string;
  readonly mediaType?: string;
  readonly etag?: string;
};

export type UploadManifestResponse = Descriptor & {
  readonly subjectDigest?: string;
};

export type CheckManifestResponse = Descriptor;

export type GetManifestResponse = Descriptor & {
  readonly body: unknown;
  readonly etag?: string;
};

export type RegistryFetchOptions = Pick<
  FetchOptions,
  'proxy' | 'noProxy' | 'retry' | 'timeout'
>;

export class RegistryClient {
  readonly #baseURL: string;
  readonly #repository: string;
  #fetch: FetchInterface;

  constructor(
    registry: string,
    repository: string,
    opts?: RegistryFetchOptions
  ) {
    this.#repository = repository;
    this.#fetch = fetch.defaults(opts);

    // Use http for localhost registries, https otherwise
    const hostname = new URL(`http://${registry}`).hostname;
    /* istanbul ignore next */
    const protocol =
      hostname === 'localhost' || hostname === '127.0.0.1' ? 'http' : 'https';
    this.#baseURL = `${protocol}://${registry}`;
  }

  // Authenticate with the registry. Sends an unauthenticated request to the
  // registry in order to get an auth challenge. If the challenge scheme is
  // "basic" we don't need a token and can authenticate requests using basic
  // auth. Otherwise, we fetch a token from the auth server and use that to
  // authenticate requests.
  // https://github.com/google/go-containerregistry/blob/main/pkg/authn/README.md#the-registry
  async signIn(creds: Credentials): Promise<void> {
    // Ensure we include an auth headers if they are present
    this.#fetch = this.#fetch.defaults({ headers: creds.headers });

    // Initiate a blob upload to get the auth challenge
    const probeResponse = await this.#fetch(
      `${this.#baseURL}/v2/${this.#repository}/blobs/uploads/`,
      { method: 'POST' }
    );

    // If we get a 200 response, we're already authenticated
    if (probeResponse.status === 200) {
      return;
    }

    const authHeader =
      probeResponse.headers.get(HEADER_AUTHENTICATE) ||
      /* istanbul ignore next */ '';
    const challenge = parseChallenge(authHeader);

    // If the challenge scheme is "basic" we don't need a token and can
    // authenticate requests using basic auth
    if (challenge.scheme === 'basic') {
      const basicAuth = toBasicAuth(creds);
      this.#fetch = this.#fetch.defaults({
        headers: { [HEADER_AUTHORIZATION]: `Basic ${basicAuth}` },
      });
      return;
    }

    let token: string | undefined;
    if (creds.username === '<token>') {
      // If the OAUth2 token request fails, try to fetch a distribution token
      token = await this.#fetchOAuth2Token(creds, challenge).catch(
        () => undefined
      );
    }

    if (!token) {
      token = await this.#fetchDistributionToken(creds, challenge);
    }

    // Ensure the token is sent with all future requests
    this.#fetch = this.#fetch.defaults({
      headers: { [HEADER_AUTHORIZATION]: `Bearer ${token}` },
    });
  }

  // Check the registry API version
  async checkVersion(): Promise<string> {
    const response = await this.#fetch(`${this.#baseURL}/v2/`);

    return response.headers.get(HEADER_API_VERSION) || '';
  }

  // Upload a blob to the registry using the post/put method. Calculates the
  // digest of the blob and checks to make sure the blob doesn't already exist
  // in the registry before uploading.
  async uploadBlob(blob: Buffer): Promise<UploadBlobResponse> {
    const digest = RegistryClient.digest(blob);
    const size = blob.length;

    // Check if blob already exists
    const headResponse = await this.#fetch(
      `${this.#baseURL}/v2/${this.#repository}/blobs/${digest}`,
      { method: 'HEAD', redirect: 'follow' }
    );

    if (headResponse.status === 200) {
      return {
        mediaType: CONTENT_TYPE_OCTET_STREAM,
        digest,
        size,
      };
    }

    // Retrieve upload location (session ID)
    const postResponse = await this.#fetch(
      `${this.#baseURL}/v2/${this.#repository}/blobs/uploads/`,
      { method: 'POST' }
    ).then(ensureStatus(202));

    const location = postResponse.headers.get(HEADER_LOCATION);
    if (!location) {
      throw new Error('Missing location for blob upload');
    }

    // Translate location to a full URL
    const uploadLocation = new URL(
      location.startsWith('/') ? `${this.#baseURL}${location}` : location
    );

    // Add digest to query string
    uploadLocation.searchParams.set('digest', digest);

    // Upload blob
    await this.#fetch(uploadLocation.href, {
      method: 'PUT',
      body: blob,
      headers: { [HEADER_CONTENT_TYPE]: CONTENT_TYPE_OCTET_STREAM },
    }).then(ensureStatus(201));

    return { mediaType: CONTENT_TYPE_OCTET_STREAM, digest, size };
  }

  // Checks for the existence of a manifest by reference
  async checkManifest(reference: string): Promise<CheckManifestResponse> {
    const response = await this.#fetch(
      `${this.#baseURL}/v2/${this.#repository}/manifests/${reference}`,
      {
        method: 'HEAD',
        headers: { [HEADER_ACCEPT]: ALL_MANIFEST_MEDIA_TYPES },
      }
    ).then(ensureStatus(200));

    const mediaType =
      response.headers.get(HEADER_CONTENT_TYPE) ||
      /* istanbul ignore next */ '';
    const digest =
      response.headers.get(HEADER_DIGEST) || /* istanbul ignore next */ '';
    const size =
      Number(response.headers.get(HEADER_CONTENT_LENGTH)) ||
      /* istanbul ignore next */ 0;

    return { mediaType, digest, size };
  }

  // Retrieves a manifest by reference
  async getManifest(reference: string): Promise<GetManifestResponse> {
    const response = await this.#fetch(
      `${this.#baseURL}/v2/${this.#repository}/manifests/${reference}`,
      {
        headers: { [HEADER_ACCEPT]: ALL_MANIFEST_MEDIA_TYPES },
      }
    ).then(ensureStatus(200));

    const body = await response.json();
    const mediaType =
      response.headers.get(HEADER_CONTENT_TYPE) ||
      /* istanbul ignore next */ '';
    const digest =
      response.headers.get(HEADER_DIGEST) || /* istanbul ignore next */ '';
    const size = Number(response.headers.get(HEADER_CONTENT_LENGTH)) || 0;
    const etag = response.headers.get(HEADER_ETAG) || undefined;

    return { body, mediaType, digest, size, etag };
  }

  // Uploads a manifest by digest. If specified, the reference will be used as
  // the manifest tag.
  async uploadManifest(
    manifest: string,
    options: UploadManifestOptions = {}
  ): Promise<UploadManifestResponse> {
    const digest = RegistryClient.digest(manifest);
    const reference = options.reference || digest;
    const contentType = options.mediaType || CONTENT_TYPE_OCI_MANIFEST;

    const headers: HeadersInit = { [HEADER_CONTENT_TYPE]: contentType };
    if (options.etag) {
      headers[HEADER_IF_MATCH] = options.etag;
    }

    const response = await this.#fetch(
      `${this.#baseURL}/v2/${this.#repository}/manifests/${reference}`,
      { method: 'PUT', body: manifest, headers }
    ).then(ensureStatus(201));

    const subjectDigest = response.headers.get(HEADER_OCI_SUBJECT) || undefined;

    return {
      mediaType: contentType,
      digest,
      size: manifest.length,
      subjectDigest,
    };
  }

  // Returns true if the registry supports the referrers API
  async pingReferrers(): Promise<boolean> {
    const response = await this.#fetch(
      `${this.#baseURL}/v2/${this.#repository}/referrers/${ZERO_DIGEST}`
    );

    return response.status === 200;
  }

  async #fetchDistributionToken(
    creds: Credentials,
    challenge: AuthChallenge
  ): Promise<string> {
    const basicAuth = toBasicAuth(creds);

    const authURL = new URL(challenge.realm);
    authURL.searchParams.set('service', challenge.service);
    authURL.searchParams.set('scope', challenge.scope);

    // Make token request with basic auth
    const tokenResponse = await this.#fetch(authURL.toString(), {
      headers: { [HEADER_AUTHORIZATION]: `Basic ${basicAuth}` },
    }).then(ensureStatus(200));

    return tokenResponse.json().then((json) => json.access_token || json.token);
  }

  async #fetchOAuth2Token(
    creds: Credentials,
    challenge: AuthChallenge
  ): Promise<string> {
    const body = new URLSearchParams({
      service: challenge.service,
      scope: challenge.scope,
      username: creds.username,
      password: creds.password,
      grant_type: 'password',
    });

    // Make OAuth token request
    const tokenResponse = await this.#fetch(challenge.realm, {
      method: 'POST',
      body,
    }).then(ensureStatus(200));

    return tokenResponse.json().then((json) => json.access_token);
  }

  private static digest(blob: crypto.BinaryLike): string {
    const hash = crypto.createHash('sha256');
    hash.update(blob);
    return `sha256:${hash.digest('hex')}`;
  }
}

type AuthChallenge = {
  scheme: 'basic' | 'bearer';
  realm: string;
  service: string;
  scope: string;
};

// Parses an auth challenge header into its components
// https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
function parseChallenge(challenge: string): AuthChallenge {
  // Account for the possibility of spaces in the auth params
  const [scheme, ...rest] = challenge.split(' ');
  const authParams = rest.join(' ');

  if (!['Basic', 'Bearer'].includes(scheme)) {
    throw new Error(`Invalid challenge: ${challenge}`);
  }

  return {
    scheme: scheme.toLocaleLowerCase() as 'basic' | 'bearer',
    realm: singleMatch(authParams, /realm="(.+?)"/),
    service: singleMatch(authParams, /service="(.+?)"/),
    scope: singleMatch(authParams, /scope="(.+?)"/),
  };
}

// Returns the first capture group of a regex match, or an empty string
const singleMatch = (str: string, regex: RegExp): string =>
  str.match(regex)?.[1] || '';
