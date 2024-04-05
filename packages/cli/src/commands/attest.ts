import color from '@oclif/color';
import { Args, Command, Flags } from '@oclif/core';
import { SerializedBundle, bundleToJSON } from '@sigstore/bundle';
import {
  Bundle,
  BundleBuilder,
  CIContextProvider,
  DEFAULT_REKOR_URL,
  DSSEBundleBuilder,
  FulcioSigner,
  IdentityProvider,
  RekorWitness,
  TSAWitness,
  Witness,
} from '@sigstore/sign';
import fs from 'fs/promises';
import { OAuthIdentityProvider } from '../oauth';

const OIDC_AUDIENCE = 'sigstore';

type SignOptions = {
  fulcioURL: string;
  identityProvider: IdentityProvider;
  rekorURL?: string;
  tsaServerURL?: string;
  timeout?: number;
};

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
    timeout: Flags.integer({
      description: 'timeout in seconds for API requests',
      default: 5,
      required: false,
    }),
  };

  static override args = {
    file: Args.file({
      description: 'file to attest',
      required: true,
      exists: true,
    }),
  };

  public async run(): Promise<SerializedBundle> {
    const { args, flags } = await this.parse(Attest);

    // If we're running in CI, we don't want to try to authenticate with an
    // OAuth provider because we won't be able to interactively authenticate.
    const identityProvider =
      'CI' in process.env && process.env.CI !== 'false'
        ? new CIContextProvider(OIDC_AUDIENCE)
        : new OAuthIdentityProvider({
            issuer: flags['oidc-issuer'],
            clientID: flags['oidc-client-id'],
            clientSecret: flags['oidc-client-secret'],
            redirectURL: flags['oidc-redirect-url'],
          });

    const options: SignOptions = {
      fulcioURL: flags['fulcio-url'],
      tsaServerURL: flags['tsa-server-url'],
      rekorURL: flags['tlog-upload'] ? flags['rekor-url'] : undefined,
      identityProvider,
      timeout: flags.timeout * 1000,
    };

    const bundler = initBundleBuilder(options);

    const bundle = await fs
      .readFile(args.file)
      .then((data) => bundler.create({ data, type: flags['payload-type'] }));

    const jsonBundle = bundleToJSON(bundle);
    if (uploadedToTLog(bundle)) {
      this.printRekorEntry(flags['rekor-url'], bundle);
    }

    if (flags['output-file']) {
      await fs.writeFile(flags['output-file'], JSON.stringify(jsonBundle));
    } else {
      this.log(JSON.stringify(jsonBundle));
    }

    return jsonBundle;
  }

  private printRekorEntry(baseURL: string, bundle: Bundle) {
    const url =
      baseURL === DEFAULT_REKOR_URL
        ? `https://search.sigstore.dev`
        : `${baseURL}/api/v1/log/entries`;
    const logIndex = bundle.verificationMaterial.tlogEntries[0].logIndex;
    this.logToStderr(
      color.yellow(`Created entry at index ${logIndex}, available at`)
    );
    this.logToStderr(color.yellow(`${url}?logIndex=${logIndex}`));
  }
}

function uploadedToTLog(bundle: Bundle): boolean {
  return bundle.verificationMaterial.tlogEntries.length > 0;
}

const initBundleBuilder = (opts: SignOptions): BundleBuilder => {
  const witnesses: Witness[] = [];

  const signer = new FulcioSigner({
    identityProvider: opts.identityProvider,
    fulcioBaseURL: opts.fulcioURL,
    timeout: opts.timeout,
  });

  if (opts.rekorURL) {
    witnesses.push(
      new RekorWitness({
        rekorBaseURL: opts.rekorURL,
        entryType: 'intoto',
        timeout: opts.timeout,
      })
    );
  }

  if (opts.tsaServerURL) {
    witnesses.push(
      new TSAWitness({
        tsaBaseURL: opts.tsaServerURL,
        timeout: opts.timeout,
      })
    );
  }

  // Build the bundle with the singleCertificate option which will
  // trigger the creation of v0.3 DSSE bundles
  return new DSSEBundleBuilder({ signer, witnesses, singleCertificate: true });
};
