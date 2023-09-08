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

/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { Crypto } from '@peculiar/webcrypto';
import * as pkijs from 'pkijs';
import { generateKeyPair } from '../util/key';
import { initializeCA } from './ca';
import { initializeCTLog } from './ctlog';

describe('CA', () => {
  const rootKeyPair = generateKeyPair();
  const crypto = new pkijs.CryptoEngine({ crypto: new Crypto() });

  beforeEach(() => {
    pkijs.setEngine('test', crypto);
  });

  const extension = {
    oid: '1.3.6.1.4.1.57264.1.20',
    value: 'workflow_dispatch',
  };

  const subjectAltName = 'testsan';

  describe('#rootCertificate', () => {
    it('returns the root certificate', async () => {
      const ca = await initializeCA(rootKeyPair);
      const root = ca.rootCertificate;

      const cert = pkijs.Certificate.fromBER(root);
      expect(cert.issuer.typesAndValues[0].value.valueBlock.value).toBe(
        'sigstore'
      );
      expect(cert.issuer.typesAndValues[1].value.valueBlock.value).toBe(
        'sigstore.mock'
      );
    });
  });

  describe('#issueCertificate', () => {
    const { publicKey } = generateKeyPair('P-256');

    const keyBytes = publicKey.export({ format: 'der', type: 'spki' });

    describe('when no CT log is provided', () => {
      it('issues a cert', async () => {
        const ca = await initializeCA(rootKeyPair);

        // Issue a certificate with the key above
        const signingCert = await ca.issueCertificate({
          publicKey: keyBytes,
          subjectAltName,
        });
        expect(signingCert).toBeDefined();

        const cert = pkijs.Certificate.fromBER(signingCert);
        expect(cert.issuer.typesAndValues[0].value.valueBlock.value).toBe(
          'sigstore'
        );
        expect(cert.issuer.typesAndValues[1].value.valueBlock.value).toBe(
          'sigstore.mock'
        );
      });

      it('issue a cert with the correct key', async () => {
        const ca = await initializeCA(rootKeyPair);

        // Issue a certificate with the key above
        const signingCert = await ca.issueCertificate({
          publicKey: keyBytes,
          subjectAltName,
        });

        // Check that the key is correct
        const cert = pkijs.Certificate.fromBER(signingCert);
        const certKey = await cert.getPublicKey();
        const cerKeyBuf = await crypto.exportKey('spki', certKey);
        expect(Buffer.from(cerKeyBuf).toString('base64')).toBe(
          keyBytes.toString('base64')
        );
      });

      it('issue a cert with the correct SAN', async () => {
        const ca = await initializeCA(rootKeyPair);

        // Issue a certificate with the key above
        const signingCert = await ca.issueCertificate({
          publicKey: keyBytes,
          subjectAltName,
        });

        // Check that the key is correct
        const cert = pkijs.Certificate.fromBER(signingCert);

        expect.assertions(1);
        cert.extensions!.forEach((ext) => {
          if (ext.extnID === pkijs.id_SubjectAltName) {
            expect(ext.parsedValue.altNames[0].value).toBe(subjectAltName);
          }
        });
      });

      it('issue a cert chained back to the root cert', async () => {
        const ca = await initializeCA(rootKeyPair);

        // Issue a certificate with the key above
        const signingCert = await ca.issueCertificate({
          publicKey: keyBytes,
          subjectAltName: 'test',
        });

        const leaf = pkijs.Certificate.fromBER(signingCert);
        const root = pkijs.Certificate.fromBER(ca.rootCertificate);

        const ccve = new pkijs.CertificateChainValidationEngine({
          trustedCerts: [root],
          certs: [leaf],
          checkDate: new Date(),
        });

        const result = await ccve.verify({}, crypto);
        expect(result.result).toBe(true);
        expect(result.certificatePath).toHaveLength(2);
      });
    });

    describe('when a custom extension is provided', () => {
      it('issues a cert with the extension', async () => {
        const ca = await initializeCA(rootKeyPair);

        // Issue a certificate with the key above
        const signingCert = await ca.issueCertificate({
          publicKey: keyBytes,
          subjectAltName: 'test',
          extensions: [extension],
        });

        const cert = pkijs.Certificate.fromBER(signingCert);

        expect.assertions(1);
        cert.extensions!.forEach((ext) => {
          if (ext.extnID === extension.oid) {
            expect(ext.parsedValue.valueBlock.value).toBe(extension.value);
          }
        });
      });
    });

    describe('when a CT log is provided', () => {
      it('issues a cert with a verifiable SCT', async () => {
        const ctLog = await initializeCTLog(rootKeyPair);
        const ca = await initializeCA(rootKeyPair, ctLog);

        // Issue a certificate with the key above
        const signingCert = await ca.issueCertificate({
          publicKey: keyBytes,
          subjectAltName: 'test',
        });

        // Verification material
        const root = ca.rootCertificate;
        const ctLogList = [
          {
            log_id: ctLog.logID.toString('base64'),
            key: ctLog.publicKey.toString('base64'),
          },
        ];

        const cert = pkijs.Certificate.fromBER(signingCert);
        // Verify the SCT on the issued certificate
        const result = await pkijs.verifySCTsForCertificate(
          cert,
          pkijs.Certificate.fromBER(root),
          ctLogList,
          0,
          crypto
        );
        expect(result).toHaveLength(1);
        expect(result[0]).toBe(true);
      });
    });
  });
});
