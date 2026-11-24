/*
Copyright 2026 The Sigstore Authors.

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
import { restoreNock } from '@sigstore/jest';
import net from 'net';
import nock from 'nock';

describe('restoreNock', () => {
  it('restores the shared TUF mock interceptor', () => {
    nock.restore();
    const originalConnect = net.Socket.prototype.connect;
    nock.activate();
    const mockRepo: typeof import('@tufjs/repo-mock') = require('@tufjs/repo-mock');
    const scope = mockRepo.default([]);

    try {
      expect(
        require.resolve('nock', {
          paths: [require.resolve('@tufjs/repo-mock')],
        })
      ).toBe(require.resolve('nock'));
      expect(net.Socket.prototype.connect).not.toBe(originalConnect);
      expect(nock.isActive()).toBe(false);
    } finally {
      try {
        scope.teardown();
      } finally {
        restoreNock(require.resolve('@tufjs/repo-mock'));
      }
    }

    expect(net.Socket.prototype.connect).toBe(originalConnect);
    expect(nock.isActive()).toBe(true);
  });

  it('restores the directly resolved Nock instance', () => {
    nock.activate();
    try {
      expect(nock.isActive()).toBe(true);
      restoreNock(require.resolve('nock'));
      expect(nock.isActive()).toBe(false);
    } finally {
      nock.restore();
    }
  });
});
