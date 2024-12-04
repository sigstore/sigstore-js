import { Args, Command, Flags } from '@oclif/core';
import { Bundle, bundleFromJSON } from '@sigstore/bundle';
import { crypto, pem } from '@sigstore/core';
import { toSignedEntity, Verifier } from '@sigstore/verify';
import fs from 'fs/promises';
import { trustMaterialFromPath, trustMaterialFromTUF } from '../trust';

export default class Verify extends Command {
  static override flags = {
    signature: Flags.string({
      description: 'path to the signature to verify',
      required: true,
    }),
    certificate: Flags.string({
      description: 'path to signing certificate to verify',
      required: true,
    }),
    'certificate-identity': Flags.string({
      description:
        'The expected identity in the signing ceritifcate SAN extension',
      required: true,
    }),
    'certificate-oidc-issuer': Flags.string({
      description: 'the expected OIDC issuer for the signing certificate',
      required: true,
    }),
    'trusted-root': Flags.string({
      description: 'path to trusted root',
      required: false,
    }),
    staging: Flags.boolean({
      description: 'whether to use the staging environment',
      default: false,
    }),
  };

  static override args = {
    file: Args.file({
      description: 'artifact to verify',
      required: true,
      exists: true,
    }),
  };

  public async run(): Promise<void> {
    const { args, flags } = await this.parse(Verify);

    const trustedRootPath = flags['trusted-root'];
    const trustMaterial = trustedRootPath
      ? await trustMaterialFromPath(trustedRootPath)
      : await trustMaterialFromTUF(flags['staging']);

    const verifier = new Verifier(trustMaterial, {
      tlogThreshold: 0,
      tsaThreshold: 0,
    });

    // Read the artifact, certificate, and signature and assemble them into a
    // Sigstore bundle
    const artifact = await fs.readFile(args.file);
    const certificate = await fs
      .readFile(flags.certificate)
      .then((data) => data.toString());
    const signature = await fs
      .readFile(flags.signature)
      .then((data) => data.toString());

    const bundle = toBundle(artifact, certificate, signature);
    const signedEntity = toSignedEntity(bundle, artifact);

    const policy = {
      subjectAlternativeName: flags['certificate-identity'],
      extensions: { issuer: flags['certificate-oidc-issuer'] },
    };

    verifier.verify(signedEntity, policy);
  }
}

// Construct a Sigstore bundle from the loose artifact, certificate, and
// signature
function toBundle(
  artifact: Buffer,
  certificate: string,
  signature: string
): Bundle {
  const artifactDigest = crypto.digest('sha256', artifact);
  const certBytes = pem.toDER(certificate);

  return bundleFromJSON({
    mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
    verificationMaterial: {
      certificate: {
        rawBytes: certBytes.toString('base64'),
      },
      publicKey: undefined,
      x509CertificateChain: undefined,
      tlogEntries: [],
      timestampVerificationData: undefined,
    },
    dsseEnvelope: undefined,
    messageSignature: {
      messageDigest: {
        algorithm: 'SHA2_256',
        digest: artifactDigest.toString('base64'),
      },
      signature,
    },
  });
}
