import color from '@oclif/color';
import { Args, Command, Flags } from '@oclif/core';
import fs from 'fs/promises';
import * as sigstore from 'sigstore';
import { OAuthIdentityProvider } from '../oauth';

import type { IdentityProvider } from 'sigstore';

export default class Attest extends Command {
  static override description = 'attest the supplied file';
  static override examples = [
    '<%= config.bin %> <%= command.id %> ./statement.json',
  ];
  static override enableJsonFlag = true;

  static override flags = {
    'fulcio-url': Flags.string({
      description: 'URL to the Sigstore PKI server',
      default: 'https://fulcio.sigstore.dev',
      required: false,
    }),
    'rekor-url': Flags.string({
      description: 'URL to the Rekor transparency log',
      default: 'https://rekor.sigstore.dev',
      required: false,
    }),
    'tsa-server-url': Flags.string({
      description: 'URL to the Timestamping Authority',
      required: false,
    }),
    'tlog-upload': Flags.boolean({
      description: 'whether or not to upload entry to the transparency log',
      default: true,
      required: false,
      allowNo: true,
    }),
    'oidc-client-id': Flags.string({
      description: 'OIDC client ID for application',
      default: 'sigstore',
      required: false,
    }),
    'oidc-client-secret': Flags.string({
      description: 'OIDC client secret for application',
      required: false,
    }),
    'oidc-issuer': Flags.string({
      description: 'OIDC provider to be used to issue ID token',
      default: 'https://oauth2.sigstore.dev/auth',
      required: false,
    }),
    'oidc-redirect-url': Flags.string({
      description: 'OIDC redirect URL',
      required: false,
      env: 'OIDC_REDIRECT_URL',
    }),
    'payload-type': Flags.string({
      char: 't',
      description: 'MIME or content type to apply to the DSSE envelope',
      default: 'application/vnd.in-toto+json',
      required: false,
      aliases: ['type'],
    }),
    'output-file': Flags.string({
      char: 'o',
      description: 'write output to file',
      required: false,
      aliases: ['output', 'out'],
    }),
    'identity-token': Flags.string({
      description: 'OIDC identity token',
      required: false,
      hidden: true,
    }),
  };

  static override args = {
    file: Args.file({
      description: 'file to attest',
      required: true,
      exists: true,
    }),
  };

  public async run(): Promise<sigstore.Bundle> {
    const { args, flags } = await this.parse(Attest);
    let identityProvider: IdentityProvider | undefined;

    if (!flags['identity-token']) {
      // If we're running in CI, we don't want to try to authenticate with an
      // OAuth provider because we won't be able to interactively authenticate.
      // Leaving the identity provider undefined will cause the attest function
      // to use the default identity provider, which will retrieve an OIDC
      // token from the environment.
      if (!('CI' in process.env) || process.env.CI === 'false') {
        identityProvider = new OAuthIdentityProvider({
          issuer: flags['oidc-issuer'],
          clientID: flags['oidc-client-id'],
          clientSecret: flags['oidc-client-secret'],
          redirectURL: flags['oidc-redirect-url'],
        });
      }
    }

    const options: Parameters<typeof sigstore.attest>[2] = {
      rekorURL: flags['rekor-url'],
      fulcioURL: flags['fulcio-url'],
      tsaServerURL: flags['tsa-server-url'],
      tlogUpload: flags['tlog-upload'],
      identityToken: flags['identity-token'],
      identityProvider,
    };

    const bundle = await fs
      .readFile(args.file)
      .then((data) => sigstore.attest(data, flags['payload-type'], options));

    if (uploadedToTLog(bundle)) {
      this.printRekorEntry(flags['rekor-url'], bundle);
    }

    if (flags['output-file']) {
      await fs.writeFile(flags['output-file'], JSON.stringify(bundle));
    } else {
      this.log(JSON.stringify(bundle));
    }

    return bundle;
  }

  private printRekorEntry(baseURL: string, bundle: sigstore.Bundle) {
    const url =
      baseURL === sigstore.DEFAULT_REKOR_URL
        ? `https://search.sigstore.dev`
        : `${baseURL}/api/v1/log/entries`;
    const logIndex = bundle.verificationMaterial.tlogEntries[0].logIndex;
    this.logToStderr(
      color.yellow(`Created entry at index ${logIndex}, available at`)
    );
    this.logToStderr(color.yellow(`${url}?logIndex=${logIndex}`));
  }
}

function uploadedToTLog(bundle: sigstore.Bundle): boolean {
  return bundle.verificationMaterial.tlogEntries.length > 0;
}
