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
    'certificate-issuer': Flags.string({
      description:
        "Value that must appear in the signing certificate's issuer extension (OID 1.3.6.1.4.1.57264.1.1 or 1.3.6.1.4.1.57264.1.8). Not verified if no value is supplied",
    }),
    'certificate-identity-email': Flags.string({
      description:
        "Email address which must appear in the signing certificate's Subject Alternative Name (SAN) extension. Not verified if no value is supplied",
      dependsOn: ['certificate-issuer'],
      exclusive: ['certificate-identity-uri'],
    }),
    'certificate-identity-uri': Flags.string({
      description:
        "URI which must appear in the signing certificate's Subject Alternative Name (SAN) extension. Not verified if no value is supplied",
      dependsOn: ['certificate-issuer'],
      exclusive: ['certificate-identity-email'],
    }),
    'tuf-mirror-url': Flags.string({
      description: 'Base URL for the Sigstore TUF repository',
    }),
    'tuf-root-path': Flags.directory({
      description: 'Path to the initial trust root for the TUF repository',
    }),
    'tuf-cache-path': Flags.directory({
      description:
        'Absolute path to the directory to be used for caching downloaded TUF metadata and targets',
    }),
    'tuf-force-cache': Flags.boolean({
      description:
        'Whether to give precedence to cached, un-expired TUF metadata and targets over remote versions',
      default: false,
      required: false,
    }),
    'blob-file': Flags.file({
      description:
        'File containing data to verify. Only required if bundle was not signed using attest',
      exists: true,
      exclusive: ['blob'],
    }),
    blob: Flags.string({
      description:
        'Base64 encoded data to verify. Only required if bundle was not signed using attest',
      exclusive: ['blob-file'],
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
      certificateIssuer: flags['certificate-issuer'],
      certificateIdentityEmail: flags['certificate-identity-email'],
      certificateIdentityURI: flags['certificate-identity-uri'],
      tufMirrorURL: flags['tuf-mirror-url'],
      tufRootPath: flags['tuf-root-path'],
      tufCachePath: flags['tuf-cache-path'],
      tufForceCache: flags['tuf-force-cache'],
    };

    const bundle = await fs
      .readFile(args.bundle)
      .then((data) => JSON.parse(data.toString()));

    let blob: Buffer | undefined;
    if (flags['blob-file']) {
      blob = await fs.readFile(flags['blob-file']).then(Buffer.from);
    } else if (flags['blob']) {
      blob = Buffer.from(flags['data'], 'base64');
    }

    return (
      blob
        ? sigstore.verify(bundle, blob, options)
        : sigstore.verify(bundle, options)
    ).then(() => {
      this.logToStderr('Verification succeeded');
      return { verified: true };
    });
  }
}
