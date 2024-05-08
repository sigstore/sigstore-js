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
import { constants as httpConstants } from 'http2';
import fetch, { FetchOptions } from 'make-fetch-happen';
import { log } from 'proc-log';
import promiseRetry from 'promise-retry';
import { ua } from '../util';
import { HTTPError } from './error';

const {
  HTTP2_HEADER_LOCATION,
  HTTP2_HEADER_CONTENT_TYPE,
  HTTP2_HEADER_USER_AGENT,
  HTTP_STATUS_INTERNAL_SERVER_ERROR,
  HTTP_STATUS_TOO_MANY_REQUESTS,
  HTTP_STATUS_REQUEST_TIMEOUT,
} = httpConstants;

type Response = Awaited<ReturnType<typeof fetch>>;
type Retry = FetchOptions['retry'];

export async function fetchWithRetry(
  url: string,
  options: FetchOptions
): Promise<Response> {
  return promiseRetry<Response>(async (retry, attemptNum) => {
    const method = options.method || 'POST';
    const headers = {
      [HTTP2_HEADER_USER_AGENT]: ua.getUserAgent(),
      ...options.headers,
    };

    const response = await fetch(url, {
      method,
      headers,
      body: options.body,
      timeout: options.timeout,
      retry: false, // We're handling retries ourselves
    }).catch((reason) => {
      log.http(
        'fetch',
        `${method} ${url} attempt ${attemptNum} failed with ${reason}`
      );
      return retry(reason);
    });

    if (response.ok) {
      return response;
    } else {
      const error = await errorFromResponse(response);
      log.http(
        'fetch',
        `${method} ${url} attempt ${attemptNum} failed with ${response.status}`
      );

      if (retryable(response.status)) {
        return retry(error);
      } else {
        throw error;
      }
    }
  }, retryOpts(options.retry));
}

// Translate a Response into an HTTPError instance. This will attempt to parse
// the response body for a message, but will default to the statusText if none
// is found.
const errorFromResponse = async (response: Response): Promise<HTTPError> => {
  let message = response.statusText;
  const location = response.headers?.get(HTTP2_HEADER_LOCATION) || undefined;
  const contentType = response.headers?.get(HTTP2_HEADER_CONTENT_TYPE);

  // If response type is JSON, try to parse the body for a message
  if (contentType?.includes('application/json')) {
    try {
      const body = await response.json();
      message = body.message || message;
    } catch (e) {
      // ignore
    }
  }

  return new HTTPError({
    status: response.status,
    message: message,
    location: location,
  });
};

// Determine if a status code is retryable. This includes 5xx errors, 408, and
// 429.
const retryable = (status: number): boolean =>
  [HTTP_STATUS_REQUEST_TIMEOUT, HTTP_STATUS_TOO_MANY_REQUESTS].includes(
    status
  ) || status >= HTTP_STATUS_INTERNAL_SERVER_ERROR;

// Normalize the retry options to the format expected by promise-retry
const retryOpts = (retry?: Retry): { retries: number } => {
  if (typeof retry === 'boolean') {
    return { retries: retry ? 1 : 0 };
  } else if (typeof retry === 'number') {
    return { retries: retry };
  } else {
    return { retries: 0, ...retry };
  }
};
