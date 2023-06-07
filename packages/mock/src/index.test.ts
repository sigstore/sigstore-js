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
import {
  HandlerFn,
  fulcioHandler,
  initializeCA,
  initializeCTLog,
  initializeTLog,
  initializeTSA,
  mockFulcio,
  mockRekor,
  mockTSA,
  rekorHandler,
  tsaHandler,
} from '.';

it('exports types', () => {
  const handlerFn: HandlerFn = async () => ({
    statusCode: 200,
    response: 'ok',
  });
  expect(handlerFn).toBeDefined();
});

it('exports functions', () => {
  expect(initializeCA).toBeDefined();
  expect(initializeCTLog).toBeDefined();
  expect(initializeTLog).toBeDefined();
  expect(initializeTSA).toBeDefined();
  expect(fulcioHandler).toBeDefined();
  expect(rekorHandler).toBeDefined();
  expect(tsaHandler).toBeDefined();
});

describe('exports mock functions', () => {
  afterEach(() => {
    nock.cleanAll();
  });

  describe('mockFulcio', () => {
    it('mocks fulcio', async () => {
      await mockFulcio();
      expect(nock.pendingMocks()).toHaveLength(1);
    });
  });

  describe('mockRekor', () => {
    it('mocks rekor', async () => {
      await mockRekor();
      expect(nock.pendingMocks()).toHaveLength(1);
    });
  });

  describe('mockTSA', () => {
    it('mocks tsa', async () => {
      await mockTSA();
      expect(nock.pendingMocks()).toHaveLength(1);
    });
  });
});
