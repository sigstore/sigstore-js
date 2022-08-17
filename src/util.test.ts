/*
Copyright 2022 The Sigstore Authors.

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
import { extractJWTSubject, getUserAgent, promiseAny } from './util';

describe('getUserAgent', () => {
  it('returns a user agent string', () => {
    expect(getUserAgent()).toMatch(new RegExp('sigstore-js\\/\\d+.\\d+.\\d+'));
  });
});

describe('extractJWTSubject', () => {
  describe('when the JWT is issued by accounts.google.com', () => {
    const payload = {
      iss: 'https://accounts.google.com',
      email: 'foo@bar.com',
    };

    const jwt = `.${Buffer.from(JSON.stringify(payload)).toString('base64')}.`;

    it('should return the email address', () => {
      expect(extractJWTSubject(jwt)).toBe(payload.email);
    });
  });

  describe('when the JWT is issued by sigstore.dev', () => {
    const payload = {
      iss: 'https://oauth2.sigstore.dev/auth',
      email: 'foo@bar.com',
    };

    const jwt = `.${Buffer.from(JSON.stringify(payload)).toString('base64')}.`;

    it('should return the email address', () => {
      expect(extractJWTSubject(jwt)).toBe(payload.email);
    });
  });

  describe('when the JWT is a generic JWT', () => {
    const payload = {
      iss: 'https://example.com',
      sub: 'foo@bar.com',
    };
    const jwt = `.${Buffer.from(JSON.stringify(payload)).toString('base64')}.`;

    it('should return the subject', () => {
      expect(extractJWTSubject(jwt)).toBe(payload.sub);
    });
  });

  describe('promiseAny', () => {
    describe('when all promises resolve', () => {
      it('should return the first resolved promise', async () => {
        const promise1 = Promise.resolve('foo');
        const promise2 = Promise.resolve('bar');
        const promise3 = Promise.resolve('baz');

        const result = await promiseAny([promise1, promise2, promise3]);
        expect(result).toBe('foo');
      });
    });

    describe('when only one promise resolves', () => {
      it('should return the first resolved promise', async () => {
        const promise1 = Promise.reject('err');
        const promise2 = Promise.resolve('bar');
        const promise3 = Promise.reject('err');

        const result = await promiseAny([promise1, promise2, promise3]);
        expect(result).toBe('bar');
      });
    });

    describe('when all promises reject', () => {
      it('should return all rejections', async () => {
        const promise1 = Promise.reject('err1');
        const promise2 = Promise.reject('err2');
        const promise3 = Promise.reject('err3');

        const result = promiseAny([promise1, promise2, promise3]);
        await expect(result).rejects.toEqual(['err1', 'err2', 'err3']);
      });
    });
  });
});
