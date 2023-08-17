import { Args, Command, Flags } from '@oclif/core';
import fs from 'fs/promises';
import * as sigstore from 'sigstore';

export default class Verify extends Command {
  static override description = 'verify the supplied .sigstore bundle file';
  static override examples = [
    '<%= config.bin %> <%= command.id %> ./bundle.sigstore',
  ];
  static override enableJsonFlag = true;

  static override flags = {
    'tlog-threshold': Flags.integer({
      description: 'number of transparency log entries required to verify',
      min: 0,
      default: 1,
    }),
    'ctlog-threshold': Flags.integer({
      description:
        'number of certificate transparency log entries required to verify',
      min: 0,
      default: 1,
    }),
  };

  static override args = {
    bundle: Args.file({
      description: 'bundle to verify',
      required: true,
      exists: true,
    }),
  };

  public async run(): Promise<{ verified: boolean }> {
    const { args, flags } = await this.parse(Verify);

    const options: Parameters<typeof sigstore.verify>[2] = {
      tlogThreshold: flags['tlog-threshold'],
      ctLogThreshold: flags['ctlog-threshold'],
    };

    const bundle = await fs
      .readFile(args.bundle)
      .then((data) => JSON.parse(data.toString()));

    return sigstore.verify(bundle, options).then(() => {
      this.logToStderr('Verification succeeded');
      return { verified: true };
    });
  }
}
