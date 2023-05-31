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
import { extractJWTSubject } from '../../util/oidc';

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
});
