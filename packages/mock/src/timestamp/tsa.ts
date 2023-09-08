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

import { Crypto } from '@peculiar/webcrypto';
import * as asn1js from 'asn1js';
import type { KeyPairKeyObjectResult } from 'crypto';
import * as pkijs from 'pkijs';
import { DIGEST_SHA256, SIGNING_ALGORITHM_ECDSA_SHA384 } from '../constants';
import { keyObjectToCryptoKey } from '../util/key';
import { createRootCertificate } from '../util/root-cert';

const ISSUER = 'CN=tsa,O=sigstore.mock';
const OID_TSTINFO_CONTENT_TYPE = '1.2.840.113549.1.9.16.1.4';
const OID_SIGNED_DATA_CONTENT_TYPE = '1.2.840.113549.1.7.2';

export interface TSA {
  rootCertificate: Buffer;
  timestamp: (req: TimestampRequest) => Promise<Buffer>;
}

export interface TimestampRequest {
  artifactHash: Buffer;
  hashAlgorithmOID: string;
  nonce: number;
  policyOID: string;
  certReq?: boolean;
}

export async function initializeTSA(
  keyPair: KeyPairKeyObjectResult
): Promise<TSA> {
  const cryptoKeyPair = {
    privateKey: await keyObjectToCryptoKey(keyPair.privateKey),
    publicKey: await keyObjectToCryptoKey(keyPair.publicKey),
  };
  const root = await createRootCertificate(
    ISSUER,
    cryptoKeyPair,
    SIGNING_ALGORITHM_ECDSA_SHA384
  );
  return new TSAImpl({
    rootCertificate: pkijs.Certificate.fromBER(root.cert.rawData),
    keyPair: root.keyPair,
  });
}

interface TSAOptions {
  rootCertificate: pkijs.Certificate;
  keyPair: CryptoKeyPair;
}

class TSAImpl implements TSA {
  private rootCert: pkijs.Certificate;
  private keyPair: CryptoKeyPair;
  private crypto: pkijs.ICryptoEngine;
  constructor(options: TSAOptions) {
    this.rootCert = options.rootCertificate;
    this.keyPair = options.keyPair;
    this.crypto = new pkijs.CryptoEngine({ crypto: new Crypto() });
  }

  public get rootCertificate(): Buffer {
    return Buffer.from(this.rootCert.toSchema().toBER(false));
  }

  // Create a timestamp according to
  // https://www.rfc-editor.org/rfc/rfc3161.html
  public async timestamp(req: TimestampRequest): Promise<Buffer> {
    const includeCerts = req.certReq ?? false;

    // Create the TSTInfo structure and sign it
    const tstInfo = this.tstInfo(req);
    const signedData = await this.signedData(tstInfo, includeCerts);

    // Encode the SignedData structure
    const content = new pkijs.ContentInfo({
      contentType: OID_SIGNED_DATA_CONTENT_TYPE,
      content: signedData.toSchema(true),
    });

    const tspResponse = new pkijs.TimeStampResp({
      status: new pkijs.PKIStatusInfo({ status: 0 }),
      timeStampToken: new pkijs.ContentInfo({ schema: content.toSchema() }),
    });

    return Buffer.from(tspResponse.toSchema().toBER(false));
  }

  // Assemble the TSTInfo structure from the request
  private tstInfo(req: TimestampRequest): pkijs.TSTInfo {
    return new pkijs.TSTInfo({
      version: 1,
      policy: req.policyOID,
      messageImprint: new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({
          algorithmId: req.hashAlgorithmOID,
        }),
        hashedMessage: new asn1js.OctetString({ valueHex: req.artifactHash }),
      }),
      serialNumber: new asn1js.Integer({ value: 1 }),
      genTime: new Date(),
      accuracy: new pkijs.Accuracy({ seconds: 1 }),
      nonce: new asn1js.Integer({ value: req.nonce }),
      tsa: generalName('tsa', 'sigstore.mock'),
    });
  }

  // Wrap the TSTInfo structure in a SignedData structure
  private async signedData(
    tstInfo: pkijs.TSTInfo,
    includeCerts: boolean
  ): Promise<pkijs.SignedData> {
    // The isConstructed flag makes the encoding of the
    // EncapsulatedContentInfo look more like what the real TSA returns,
    // however, it results in a reponse that is not parseable by openssl.
    // I guess we should leave it at the default but let's revisit this
    // later if we run into verification problems.
    const encapContent = new pkijs.EncapsulatedContentInfo({
      eContentType: OID_TSTINFO_CONTENT_TYPE,
      eContent: new asn1js.OctetString({
        valueHex: tstInfo.toSchema().toBER(false),
        // idBlock: { isConstructed: true },
      }),
    });

    /* istanbul ignore next */
    const signedData = new pkijs.SignedData({
      version: 1,
      encapContentInfo: encapContent,
      certificates: includeCerts ? [this.rootCert] : undefined,
      signerInfos: [
        new pkijs.SignerInfo({
          version: 1,
          sid: new pkijs.IssuerAndSerialNumber({
            issuer: this.rootCert.issuer,
            serialNumber: this.rootCert.serialNumber,
          }),
        }),
      ],
    });

    // Sign the SignedData structure
    await signedData.sign(
      this.keyPair.privateKey,
      0,
      DIGEST_SHA256,
      undefined,
      this.crypto
    );

    return signedData;
  }
}

function generalName(commonName: string, orgName: string): pkijs.GeneralName {
  return new pkijs.GeneralName({
    type: 4,
    value: new pkijs.RelativeDistinguishedNames({
      typesAndValues: [
        new pkijs.AttributeTypeAndValue({
          type: '2.5.4.10',
          value: new asn1js.PrintableString({ value: orgName }),
        }),
        new pkijs.AttributeTypeAndValue({
          type: '2.5.4.3',
          value: new asn1js.PrintableString({ value: commonName }),
        }),
      ],
    }),
  });
}
