import { Crypto, CryptoKey } from '@peculiar/webcrypto';
import * as asn1js from 'asn1js';
import * as bs from 'bytestreamjs';
import * as pkijs from 'pkijs';
import * as pvutils from 'pvutils';

const DIGEST_SHA256 = 'SHA-256';
const ALGORITHM_ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' };

export async function initializeCTLog(): Promise<CTLog> {
  const crypto = new pkijs.CryptoEngine({ crypto: new Crypto() });

  const { publicKey, privateKey } = await crypto.generateKey(
    ALGORITHM_ECDSA_P256,
    true,
    ['sign', 'verify']
  );

  const publicKeyBytes = await crypto
    .exportKey('spki', publicKey)
    .then((bytes) => Buffer.from(bytes));

  const logID = await crypto
    .digest({ name: DIGEST_SHA256 }, publicKeyBytes)
    .then((bytes) => Buffer.from(bytes));

  return new CTLogImpl({
    publicKey: publicKeyBytes,
    privateKey,
    logID,
    crypto,
  });
}

export interface CTLog {
  publicKey: Buffer;
  logID: Buffer;
  log: (
    certificate: pkijs.Certificate,
    issuerID: ArrayBuffer
  ) => Promise<pkijs.SignedCertificateTimestamp>;
}

interface CTLogOptions {
  publicKey: Buffer;
  logID: Buffer;
  privateKey: CryptoKey;
  crypto: pkijs.CryptoEngine;
}

class CTLogImpl implements CTLog {
  public readonly publicKey: Buffer;
  public readonly logID: Buffer;
  private privateKey: CryptoKey;
  private crypto: pkijs.CryptoEngine;

  constructor(options: CTLogOptions) {
    this.publicKey = options.publicKey;
    this.privateKey = options.privateKey;
    this.logID = options.logID;
    this.crypto = options.crypto;
  }

  public async log(
    certificate: pkijs.Certificate,
    issuerID: ArrayBuffer
  ): Promise<pkijs.SignedCertificateTimestamp> {
    const version = 0;
    const timestamp = new Date();
    const logID = this.logID;
    const tbs = certificate.encodeTBS().toBER();

    // Calculate the SCT signature
    const stream = new bs.SeqStream();
    stream.appendChar(version);
    stream.appendChar(0x00); // SignatureType - certificate_timestamp(0)
    stream.appendView(encodeTimeStamp(timestamp));
    stream.appendUint16(0x01); // LogEntryType = precert_entry(1)
    stream.appendView(new Uint8Array(issuerID));
    stream.appendUint24(tbs.byteLength);
    stream.appendView(new Uint8Array(tbs));
    stream.appendUint16(0x00); // extensions length

    const sig = await this.sign(stream.buffer);

    return new pkijs.SignedCertificateTimestamp({
      version,
      logID,
      timestamp,
      signature: asn1js.fromBER(sig).result,
      hashAlgorithm: 'sha256',
      signatureAlgorithm: 'ecdsa',
    });
  }

  private async sign(data: BufferSource): Promise<ArrayBuffer> {
    const { parameters } = await this.crypto.getSignatureParameters(
      this.privateKey,
      DIGEST_SHA256
    );

    parameters.algorithm;
    return this.crypto.signWithPrivateKey(
      data,
      this.privateKey,
      parameters as pkijs.CryptoEngineSignWithPrivateKeyParams
    );
  }
}

const encodeTimeStamp = (timestamp: Date): Uint8Array => {
  const timeBuffer = new ArrayBuffer(8);
  const timeView = new Uint8Array(timeBuffer);
  const baseArray = pvutils.utilToBase(timestamp.valueOf(), 8);
  timeView.set(new Uint8Array(baseArray), 8 - baseArray.byteLength);

  return timeView;
};
