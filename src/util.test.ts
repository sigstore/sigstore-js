import { base64Decode, base64Encode, extractJWTSubject } from './util';

describe('base64Decode', () => {
  it('decodes a base64 string', () => {
    const encoded = 'aGVsbG8gd29ybGQ=';
    const decoded = base64Decode(encoded);

    expect(decoded).toBe('hello world');
  });
});

describe('base64Encode', () => {
  it('encodes a string to base64', () => {
    const decoded = 'hello world';
    const encoded = base64Encode(decoded);

    expect(encoded).toBe('aGVsbG8gd29ybGQ=');
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
});
