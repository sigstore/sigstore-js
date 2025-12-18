import { Args, Command, Flags } from '@oclif/core';
import { bundleToJSON } from '@sigstore/bundle';
import { SigningConfig } from '@sigstore/protobuf-specs';
import { bundleBuilderFromSigningConfig } from '@sigstore/sign';
import fs from 'fs/promises';
import { PRODUCTION_SIGNING_CONFIG, STAGING_SIGNING_CONFIG } from '../config';

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
    'signing-config': Flags.file({
      description: 'path to signing config file',
      required: false,
      exists: true,
    }),
    'trusted-root': Flags.file({
      description: 'path to a custom trusted root to use to verify the bundle',
      required: false,
      exists: true,
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
    const identityProvider = {
      getToken: () => Promise.resolve(flags['identity-token']),
    };

    let configJson: object;
    const signingConfigPath = flags['signing-config'];
    if (signingConfigPath) {
      configJson = await fs
        .readFile(signingConfigPath, 'utf-8')
        .then((data) => JSON.parse(data));
    } else {
      if (flags['staging']) {
        configJson = STAGING_SIGNING_CONFIG;
      } else {
        configJson = PRODUCTION_SIGNING_CONFIG;
      }
    }
    const signingConfig = SigningConfig.fromJSON(configJson);

    const artifact = await fs.readFile(args.artifact);

    const builder = bundleBuilderFromSigningConfig({
      bundleType: 'messageSignature',
      signingConfig,
      identityProvider,
    });

    const bundle = await builder.create({ data: artifact });

    await fs.writeFile(flags['bundle'], JSON.stringify(bundleToJSON(bundle)));
  }
}
