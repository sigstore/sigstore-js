import { Args, Command, Flags } from '@oclif/core';
import crypto, { BinaryLike } from 'crypto';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import * as sigstore from 'sigstore';
import { TUF_STAGING_ROOT, TUF_STAGING_URL } from '../staging';

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

    const artifact = await fs.readFile(args.file);
    const certificate = await fs
      .readFile(flags.certificate)
      .then((data) => data.toString());
    const signature = await fs
      .readFile(flags.signature)
      .then((data) => data.toString());

    const bundle = toBundle(artifact, certificate, signature);

    const options: Parameters<typeof sigstore.verify>[2] = {
      certificateIdentityURI: flags['certificate-identity'],
      certificateIssuer: flags['certificate-oidc-issuer'],
      tlogThreshold: 0,
    };

    if (flags['staging']) {
      // Write the initial root.json to a temporary directory
      const tmpPath = await fs.mkdtemp(path.join(os.tmpdir(), 'sigstore-'));
      const rootPath = path.join(tmpPath, 'root.json');
      await fs.writeFile(rootPath, Buffer.from(TUF_STAGING_ROOT, 'base64'));

      options.tufMirrorURL = TUF_STAGING_URL;
      options.tufRootPath = rootPath;
    }

    sigstore.verify(bundle, artifact, options);
  }
}

function toBundle(
  artifact: Buffer,
  certificate: string,
  signature: string
): sigstore.Bundle {
  const artifactDigest = hash(artifact);
  const certBytes = toDER(certificate);

  return {
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
    verificationMaterial: {
      x509CertificateChain: {
        certificates: [{ rawBytes: certBytes.toString('base64') }],
      },
      certificate: undefined,
      publicKey: undefined,
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
  };
}

function toDER(certificate: string): Buffer {
  let der = '';

  certificate.split('\n').forEach((line) => {
    if (
      line.match(/-----BEGIN (.*)-----/) ||
      line.match(/-----END (.*)-----/)
    ) {
      return;
    }

    der += line;
  });

  return Buffer.from(der, 'base64');
}

export function hash(data: BinaryLike): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}
