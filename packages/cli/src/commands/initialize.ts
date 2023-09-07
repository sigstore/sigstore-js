import { Command, Flags } from '@oclif/core';
import { DEFAULT_MIRROR_URL, initTUF } from '@sigstore/tuf';

export default class Initialize extends Command {
  static override aliases = ['init'];
  static override description =
    'initialize the Sigstore TUF root to retrieve trusted certificates and keys for verification';
  static override examples = ['<%= config.bin %> <%= command.id %>'];

  static override flags = {
    mirror: Flags.string({
      description: 'URL to the Sigstore TUF repository',
      default: DEFAULT_MIRROR_URL,
    }),
    root: Flags.file({
      description:
        'path to the initial trusted root. Defaults to the embedded root.',
    }),
    force: Flags.boolean({
      description: 'force initialization even if the cache already exists',
      default: false,
    }),
  };

  public async run(): Promise<void> {
    const { flags } = await this.parse(Initialize);

    await initTUF({
      mirrorURL: flags.mirror,
      rootPath: flags.root,
      force: flags.force,
    });
  }
}
