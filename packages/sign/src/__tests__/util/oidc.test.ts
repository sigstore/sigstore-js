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
  describe('when the JWT has a verified email', () => {
    const payload = {
      iss: 'https://accounts.google.com',
      email: 'foo@bar.com',
      email_verified: true,
    };

    const jwt = `.${Buffer.from(JSON.stringify(payload)).toString('base64')}.`;

    it('should return the email address', () => {
      expect(extractJWTSubject(jwt)).toBe(payload.email);
    });
  });

  describe('when the JWT has an unverified email', () => {
    const payload = {
      iss: 'https://oauth2.sigstore.dev/auth',
      email: 'foo@bar.com',
      email_verified: false,
    };

    const jwt = `.${Buffer.from(JSON.stringify(payload)).toString('base64')}.`;

    it('throws an error', () => {
      expect(() => extractJWTSubject(jwt)).toThrow(
        'JWT email not verified by issuer'
      );
    });
  });

  describe('when the JWT has a sub claim', () => {
    const payload = {
      iss: 'https://example.com',
      sub: 'foo@bar.com',
    };
    const jwt = `.${Buffer.from(JSON.stringify(payload)).toString('base64')}.`;

    it('should return the subject', () => {
      expect(extractJWTSubject(jwt)).toBe(payload.sub);
    });
  });

  describe('when the JWT has neither an email nor a sub claim', () => {
    const payload = {
      iss: 'https://example.com',
    };
    const jwt = `.${Buffer.from(JSON.stringify(payload)).toString('base64')}.`;

    it('throws an error', () => {
      expect(() => extractJWTSubject(jwt)).toThrow('JWT subject not found');
    });
  });
});
