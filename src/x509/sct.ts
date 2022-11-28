import { ByteStream } from '../util/stream';

interface SCTOptions {
  version: number;
  logID: Buffer;
  timestamp: Buffer;
  extensions: Buffer;
  hashAlgorithm: number;
  signatureAlgorithm: number;
  signature: Buffer;
}

export class SignedCertificateTimestamp {
  private _version: number;
  readonly logID: Buffer;
  private _timestamp: Buffer;
  private _hashAlgorithm: number;
  private _signatureAlgorithm: number;
  readonly signature: Buffer;

  constructor(options: SCTOptions) {
    this._version = options.version;
    this.logID = options.logID;
    this._timestamp = options.timestamp;
    this._hashAlgorithm = options.hashAlgorithm;
    this._signatureAlgorithm = options.signatureAlgorithm;
    this.signature = options.signature;
  }

  get version(): string {
    switch (this._version) {
      case 0:
        return 'v1';
      default:
        return 'unknown';
    }
  }

  get timestamp(): Date {
    return new Date(Number(this._timestamp.readBigInt64BE()));
  }

  // Returns the hash algorithm used to generate the SCT's signature.
  // https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4.1
  get hashAlgorithm(): string {
    switch (this._hashAlgorithm) {
      case 0:
        return 'none';
      case 1:
        return 'md5';
      case 2:
        return 'sha1';
      case 3:
        return 'sha224';
      case 4:
        return 'sha256';
      case 5:
        return 'sha384';
      case 6:
        return 'sha512';
      default:
        return 'unknown';
    }
  }

  // Returns the signature algorithm used to generate the SCT's signature.
  // https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4.1
  get signatureAlgorithm(): string {
    switch (this._signatureAlgorithm) {
      case 0:
        return 'anonymous';
      case 1:
        return 'rsa';
      case 2:
        return 'dsa';
      case 3:
        return 'ecdsa';
      default:
        return 'unknown';
    }
  }

  // Parses a SignedCertificateTimestamp from a buffer. SCTs are encoded using
  // TLS encoding which means the fields and lengths of most fields are
  // specified as part of the SCT and TLS specs.
  // https://www.rfc-editor.org/rfc/rfc6962#section-3.2
  // https://www.rfc-editor.org/rfc/rfc5246
  public static parseBuffer(buf: Buffer): SignedCertificateTimestamp {
    const stream = new ByteStream(buf);

    // Version field is first byte
    const version = stream.get();

    // Log ID is next 32 bytes
    const logID = stream.get(32);

    // Timestamp is next 8 bytes
    const timestamp = stream.get(8);

    const extenstionLength = stream.get(2).readUInt16BE();
    const extensions = stream.get(extenstionLength);

    // Hash algo is next byte
    const hashAlgorithm = stream.get();

    // Signature algo is next byte
    const signatureAlgorithm = stream.get();

    const sigLength = stream.get(2).readUInt16BE();
    const signature = stream.get(sigLength);

    // Check that we read the entire buffer
    if (stream.position !== stream.length) {
      throw new Error('SCT buffer length mismatch');
    }

    return new SignedCertificateTimestamp({
      version,
      logID,
      timestamp,
      extensions,
      hashAlgorithm,
      signatureAlgorithm,
      signature,
    });
  }
}
