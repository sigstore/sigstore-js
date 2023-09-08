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

import { Crypto, CryptoKey } from '@peculiar/webcrypto';
import * as asn1js from 'asn1js';
import * as bs from 'bytestreamjs';
import type { KeyPairKeyObjectResult } from 'crypto';
import * as pkijs from 'pkijs';
import * as pvutils from 'pvutils';
import { DIGEST_SHA256, SIGNING_ALGORITHM_ECDSA_SHA256 } from '../constants';
import { keyObjectToCryptoKey } from '../util/key';

export interface CTLog {
  publicKey: Buffer;
  logID: Buffer;
  log: (
    certificate: ArrayBuffer,
    issuerID: ArrayBuffer
  ) => Promise<ArrayBuffer>;
}

export async function initializeCTLog(
  keyPair: KeyPairKeyObjectResult
): Promise<CTLog> {
  const crypto = new Crypto();

  // Need to translate between the Node.js crypto API and the WebCrypto API
  const privateKey = await keyObjectToCryptoKey(keyPair.privateKey);
  const publicKey = await keyObjectToCryptoKey(keyPair.publicKey);

  const publicKeyBytes = await crypto.subtle
    .exportKey('spki', publicKey)
    .then((bytes) => Buffer.from(bytes));

  const logID = await crypto.subtle
    .digest({ name: DIGEST_SHA256 }, publicKeyBytes)
    .then((bytes) => Buffer.from(bytes));

  return new CTLogImpl({
    publicKey: publicKeyBytes,
    privateKey,
    logID,
    crypto,
  });
}

interface CTLogOptions {
  publicKey: Buffer;
  logID: Buffer;
  privateKey: CryptoKey;
  crypto: Crypto;
}

class CTLogImpl implements CTLog {
  public readonly publicKey: Buffer;
  public readonly logID: Buffer;
  private privateKey: CryptoKey;
  private crypto: Crypto;

  constructor(options: CTLogOptions) {
    this.publicKey = options.publicKey;
    this.privateKey = options.privateKey;
    this.logID = options.logID;
    this.crypto = options.crypto;
  }

  public async log(
    certificate: ArrayBuffer,
    issuerID: ArrayBuffer
  ): Promise<ArrayBuffer> {
    const version = 0;
    const timestamp = new Date();
    const logID = this.logID;

    // A bit of a hack to get the TBS bytes
    const tbs = pkijs.Certificate.fromBER(certificate).encodeTBS().toBER();

    // Calculate the SCT signature
    // https://www.rfc-editor.org/rfc/rfc6962#section-3.2
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
    }).toStream().buffer;
  }

  private async sign(data: BufferSource): Promise<ArrayBuffer> {
    return this.crypto.subtle
      .sign(SIGNING_ALGORITHM_ECDSA_SHA256, this.privateKey, data)
      .then((bytes) => pkijs.createCMSECDSASignature(bytes));
  }
}

const encodeTimeStamp = (timestamp: Date): Uint8Array => {
  const timeBuffer = new ArrayBuffer(8);
  const timeView = new Uint8Array(timeBuffer);
  const baseArray = pvutils.utilToBase(timestamp.valueOf(), 8);
  timeView.set(new Uint8Array(baseArray), 8 - baseArray.byteLength);

  return timeView;
};
