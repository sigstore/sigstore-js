import { Args, Command, Flags } from '@oclif/core';
import fs from 'fs/promises';
import * as sigstore from 'sigstore';

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

    const options: Parameters<typeof sigstore.verify>[2] = {
      certificateIdentityURI: flags['certificate-identity'],
      certificateIssuer: flags['certificate-oidc-issuer'],
    };

    sigstore.verify(bundle, artifact, options);
  }
}
