import { Args, Command, Flags } from '@oclif/core';
import fs from 'fs/promises';
import * as sigstore from 'sigstore';
import { FULCIO_STAGING_URL, REKOR_STAGING_URL } from '../staging';

export default class SignBundle extends Command {
  static override flags = {
    'identity-token': Flags.string({
      description: 'OIDC identity token',
      required: true,
    }),
    bundle: Flags.string({
      description: 'path to which the bundle will be written',
      required: true,
    }),
    staging: Flags.boolean({
      description: 'whether to use the staging environment',
      default: false,
    }),
  };

  static override args = {
    artifact: Args.file({
      description: 'artifact to sign',
      required: true,
      exists: true,
    }),
  };

  public async run(): Promise<void> {
    const { args, flags } = await this.parse(SignBundle);

    const options: Parameters<typeof sigstore.sign>[1] = {
      identityToken: flags['identity-token'],
    };

    if (flags['staging']) {
      options.fulcioURL = FULCIO_STAGING_URL;
      options.rekorURL = REKOR_STAGING_URL;
    }

    const artifact = await fs.readFile(args.artifact);
    const bundle = await sigstore.sign(artifact, options);

    await fs.writeFile(flags['bundle'], JSON.stringify(bundle));
  }
}
