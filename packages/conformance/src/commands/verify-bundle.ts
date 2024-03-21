import { Args, Command, Flags } from '@oclif/core';
import { bundleFromJSON } from '@sigstore/bundle';
import { TrustedRoot } from '@sigstore/protobuf-specs';
import { Verifier, toSignedEntity, toTrustMaterial } from '@sigstore/verify';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import * as sigstore from 'sigstore';
import { TUF_STAGING_ROOT, TUF_STAGING_URL } from '../staging';

export default class VerifyBundle extends Command {
  static override flags = {
    bundle: Flags.string({
      description: 'path to bundle',
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
    const { args, flags } = await this.parse(VerifyBundle);

    const bundle = await fs
      .readFile(flags.bundle)
      .then((data) => JSON.parse(data.toString()));
    const artifact = await fs.readFile(args.file);
    const trustedRootPath = flags['trusted-root'];

    if (!trustedRootPath) {
      const options: Parameters<typeof sigstore.verify>[2] = {
        certificateIdentityURI: flags['certificate-identity'],
        certificateIssuer: flags['certificate-oidc-issuer'],
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
    } else {
      // Need to assemble the Verifier manually to pass in the trusted root
      const trustedRoot = await fs
        .readFile(trustedRootPath)
        .then((data) => JSON.parse(data.toString()));
      const trustMaterial = toTrustMaterial(TrustedRoot.fromJSON(trustedRoot));
      const signedEntity = toSignedEntity(bundleFromJSON(bundle), artifact);
      const policy = {
        subjectAlternativeName: flags['certificate-identity'],
        extensions: {
          issuer: flags['certificate-oidc-issuer'],
        },
      };

      const verifier = new Verifier(trustMaterial);
      verifier.verify(signedEntity, policy);
    }
  }
}
