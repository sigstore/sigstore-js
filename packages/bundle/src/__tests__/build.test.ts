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
import { Bundle } from '@sigstore/protobuf-specs';
import { toDSSEBundle, toMessageSignatureBundle } from '../build';

const signature = Buffer.from('signature');
const keyHint = 'hint';
const certificate = Buffer.from('certificate');

describe('toMessageSignatureBundle', () => {
  const digest = Buffer.from('digest');

  describe('when the singleCertificate option is undefined', () => {
    it('returns a valid message signature bundle', () => {
      const b = toMessageSignatureBundle({
        digest,
        signature,
        certificate,
        keyHint,
      });

      expect(b).toBeTruthy();
      expect(Bundle.toJSON(b)).toMatchSnapshot();
    });
  });

  describe('when the certificateChain option is true', () => {
    it('returns a valid message signature bundle', () => {
      const b = toMessageSignatureBundle({
        digest,
        signature,
        certificate,
        keyHint,
        certificateChain: true,
      });

      expect(b).toBeTruthy();
      expect(Bundle.toJSON(b)).toMatchSnapshot();
    });
  });
});

describe('toDSSEBundle', () => {
  const artifact = Buffer.from('data');
  const artifactType = 'text/plain';

  describe('when the singleCertificate option is undefined/false', () => {
    describe('when a public key w/ hint is provided', () => {
      it('returns a valid DSSE bundle', () => {
        const b = toDSSEBundle({
          artifact,
          artifactType,
          signature,
          keyHint,
        });

        expect(b).toBeTruthy();
        expect(Bundle.toJSON(b)).toMatchSnapshot();
      });
    });

    describe('when a public key w/o hint is provided', () => {
      it('returns a valid DSSE bundle', () => {
        const b = toDSSEBundle({
          artifact,
          artifactType,
          signature,
          singleCertificate: false,
        });

        expect(b).toBeTruthy();
        expect(Bundle.toJSON(b)).toMatchSnapshot();
      });
    });

    describe('when a certificate chain provided', () => {
      it('returns a valid DSSE bundle', () => {
        const b = toDSSEBundle({
          artifact,
          artifactType,
          signature,
          certificate,
        });

        expect(b).toBeTruthy();
        expect(Bundle.toJSON(b)).toMatchSnapshot();
      });
    });
  });

  describe('when the certificateChain option is true', () => {
    describe('when a public key w/ hint is provided', () => {
      it('returns a valid DSSE bundle', () => {
        const b = toDSSEBundle({
          artifact,
          artifactType,
          signature,
          keyHint,
          certificateChain: true,
        });

        expect(b).toBeTruthy();
        expect(Bundle.toJSON(b)).toMatchSnapshot();
      });
    });

    describe('when a public key w/o hint is provided', () => {
      it('returns a valid DSSE bundle', () => {
        const b = toDSSEBundle({
          artifact,
          artifactType,
          signature,
          certificateChain: true,
        });

        expect(b).toBeTruthy();
        expect(Bundle.toJSON(b)).toMatchSnapshot();
      });
    });

    describe('when a certificate chain provided', () => {
      it('returns a valid DSSE bundle', () => {
        const b = toDSSEBundle({
          artifact,
          artifactType,
          signature,
          certificate,
          certificateChain: true,
        });

        expect(b).toBeTruthy();
        expect(Bundle.toJSON(b)).toMatchSnapshot();
      });
    });
  });
});
