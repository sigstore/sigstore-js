/*
Copyright 2024 The Sigstore Authors.

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

const {
  HTTP_STATUS_INTERNAL_SERVER_ERROR,
  HTTP_STATUS_TOO_MANY_REQUESTS,
  HTTP_STATUS_REQUEST_TIMEOUT,
} = httpConstants;

type Response = Awaited<ReturnType<typeof fetch>>;
type Retry = FetchOptions['retry'];

const fetchWithRetry = async (
  url: string,
  options: FetchOptions = {}
): Promise<Response> => {
  return promiseRetry<Response>(async (retry, attemptNum) => {
    /* eslint-disable @typescript-eslint/no-explicit-any */
    const logRetry = (reason: any) => {
      log.http(
        'fetch',
        `${options.method} ${url} attempt ${attemptNum} failed with ${reason}`
      );
    };

    const response = await fetch(url, {
      ...options,
      retry: false, // We're handling retries ourselves
    }).catch((reason) => {
      logRetry(reason);
      return retry(reason);
    });

    if (retryable(response.status)) {
      logRetry(response.status);
      return retry(response);
    }

    return response;
  }, retryOpts(options.retry)).catch((err) => {
    // If we got an actual error, throw it
    if (err instanceof Error) {
      throw err;
    }

    // Otherwise, return the response (this is simply a retry-able response for
    // which we exceeded the retry limit)
    return err;
  });
};

// Returns a wrapped fetch function with default options
fetchWithRetry.defaults = (
  defaultOptions: FetchOptions = {},
  wrappedFetch = fetchWithRetry
) => {
  const defaultedFetch = (url: string, options: FetchOptions = {}) => {
    const finalOptions = {
      ...defaultOptions,
      ...options,
      headers: { ...defaultOptions.headers, ...options.headers },
    };
    return wrappedFetch(url, finalOptions);
  };

  defaultedFetch.defaults = (newDefaults: FetchOptions = {}) =>
    fetchWithRetry.defaults(newDefaults, defaultedFetch);

  return defaultedFetch;
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

export default fetchWithRetry;
export type FetchInterface = typeof fetchWithRetry;
export type { FetchOptions, Response };
