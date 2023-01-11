import * as sigstore from '../../../types/sigstore';
import bundles from '../../__fixtures__/bundles/';

describe('isBundleWithCertificateChain', () => {
  describe('when the bundle contains a certificate chain', () => {
    const json = bundles.dsse.valid.withSigningCert;
    const bundle = sigstore.Bundle.fromJSON(json);

    it('returns true', () => {
      expect(sigstore.isBundleWithCertificateChain(bundle)).toBe(true);
    });
  });

  describe('when the bundle does NOT contain a certificate chain', () => {
    const json = bundles.dsse.valid.withPublicKey;
    const bundle = sigstore.Bundle.fromJSON(json);

    it('returns false', () => {
      expect(sigstore.isBundleWithCertificateChain(bundle)).toBe(false);
    });
  });
});

describe('isCAVerificationOptions', () => {
  describe('when the verification options are for a CA', () => {
    const opts: sigstore.ArtifactVerificationOptions = {
      ctlogOptions: {
        detachedSct: false,
        disable: false,
        threshold: 1,
      },
      signers: {
        $case: 'certificateIdentities',
        certificateIdentities: {
          identities: [],
        },
      },
    };
    it('returns true', () => {
      expect(sigstore.isCAVerificationOptions(opts)).toBe(true);
    });
  });

  describe('when the verification options do not include ctlogOptions', () => {
    const opts: sigstore.ArtifactVerificationOptions = {
      signers: {
        $case: 'certificateIdentities',
        certificateIdentities: {
          identities: [],
        },
      },
    };

    it('returns false', () => {
      expect(sigstore.isCAVerificationOptions(opts)).toBe(false);
    });
  });

  describe('when the verification options do not include signers', () => {
    const opts: sigstore.ArtifactVerificationOptions = {
      ctlogOptions: {
        detachedSct: false,
        disable: false,
        threshold: 1,
      },
    };

    it('returns false', () => {
      expect(sigstore.isCAVerificationOptions(opts)).toBe(false);
    });
  });

  describe('when the verification options include public key signers', () => {
    const opts: sigstore.ArtifactVerificationOptions = {
      ctlogOptions: {
        detachedSct: false,
        disable: false,
        threshold: 1,
      },
      signers: {
        $case: 'publicKeys',
        publicKeys: {
          publicKeys: [],
        },
      },
    };

    it('returns false', () => {
      expect(sigstore.isCAVerificationOptions(opts)).toBe(false);
    });
  });
});
