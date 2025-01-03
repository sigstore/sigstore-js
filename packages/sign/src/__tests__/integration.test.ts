import { mockFulcio, mockRekor, mockTSA } from '@sigstore/mock';
import assert from 'assert';
import {
  DSSEBundleBuilder,
  FulcioSigner,
  MessageSignatureBundleBuilder,
  RekorWitness,
  TSAWitness,
} from '..';

describe('artifact signing', () => {
  const fulcioURL = 'https://fulcio.example.com';
  const rekorURL = 'https://rekor.example.com';
  const tsaURL = 'https://tsa.example.com';

  const subject = 'foo@bar.com';
  const oidcPayload = { sub: subject, iss: '' };
  const oidc = `.${Buffer.from(JSON.stringify(oidcPayload)).toString(
    'base64'
  )}.}`;

  const idp = { getToken: () => Promise.resolve(oidc) };

  const signer = new FulcioSigner({
    fulcioBaseURL: fulcioURL,
    identityProvider: idp,
  });
  const rekorWitness = new RekorWitness({ rekorBaseURL: rekorURL });
  const tsaWitness = new TSAWitness({ tsaBaseURL: tsaURL });

  beforeEach(async () => {
    await mockFulcio({ baseURL: fulcioURL });
    await mockRekor({ baseURL: rekorURL });
    await mockTSA({ baseURL: tsaURL });
  });

  describe('when building a message signature bundle', () => {
    const data = Buffer.from('hello, world');
    const bundler = new MessageSignatureBundleBuilder({
      signer,
      witnesses: [rekorWitness, tsaWitness],
    });

    it('returns the signed bundle', async () => {
      const bundle = await bundler.create({ data });

      expect(bundle).toBeDefined();
      expect(bundle.content.messageSignature.signature).toBeDefined();
      expect(bundle.content.messageSignature.messageDigest).toBeDefined();

      assert(
        bundle.verificationMaterial.content.$case === 'x509CertificateChain'
      );
      expect(
        bundle.verificationMaterial.content.x509CertificateChain.certificates
      ).toHaveLength(1);

      expect(bundle.verificationMaterial.tlogEntries).toHaveLength(1);
      expect(bundle.verificationMaterial.tlogEntries[0].kindVersion.kind).toBe(
        'hashedrekord'
      );

      expect(
        bundle.verificationMaterial.timestampVerificationData?.rfc3161Timestamps
      ).toHaveLength(1);
    });
  });

  describe('when building a DSSE envelope bundle', () => {
    const data = Buffer.from('hello, world');
    const bundler = new DSSEBundleBuilder({
      signer,
      witnesses: [rekorWitness, tsaWitness],
    });

    it('returns the signed bundle', async () => {
      const bundle = await bundler.create({ data, type: 'text/plain' });

      expect(bundle).toBeDefined();
      expect(bundle.content.dsseEnvelope.payloadType).toBe('text/plain');
      expect(bundle.content.dsseEnvelope.payload).toBe(data);
      expect(bundle.content.dsseEnvelope.signatures).toHaveLength(1);

      assert(bundle.verificationMaterial.content.$case === 'certificate');
      expect(bundle.verificationMaterial.content.certificate).toBeDefined();

      expect(bundle.verificationMaterial.tlogEntries).toHaveLength(1);
      expect(bundle.verificationMaterial.tlogEntries[0].kindVersion.kind).toBe(
        'dsse'
      );

      expect(
        bundle.verificationMaterial.timestampVerificationData?.rfc3161Timestamps
      ).toHaveLength(1);
    });
  });
});
