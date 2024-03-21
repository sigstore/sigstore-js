import { Args, Command, Flags } from '@oclif/core';
import fs from 'fs/promises';
import * as sigstore from 'sigstore';
import { FULCIO_STAGING_URL, REKOR_STAGING_URL } from '../staging';

export default class Sign extends Command {
  static override flags = {
    'identity-token': Flags.string({
      description: 'OIDC identity token',
      required: true,
    }),
    signature: Flags.string({
      description: 'path to which the signature will be written',
      required: true,
    }),
    certificate: Flags.string({
      description: 'path to which the certificate will be written',
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
    const { args, flags } = await this.parse(Sign);

    const options: Parameters<typeof sigstore.sign>[1] = {
      identityToken: flags['identity-token'],
    };

    if (flags['staging']) {
      options.fulcioURL = FULCIO_STAGING_URL;
      options.rekorURL = REKOR_STAGING_URL;
    }

    const artifact = await fs.readFile(args.artifact);
    const bundle = await sigstore.sign(artifact, options);

    if (bundle.messageSignature?.signature) {
      const signature = bundle.messageSignature.signature;
      await fs.writeFile(flags['signature'], signature);
    } else {
      this.error('No signature found');
    }

    if (bundle.verificationMaterial.x509CertificateChain?.certificates) {
      const certBytes =
        bundle.verificationMaterial.x509CertificateChain.certificates[0]
          .rawBytes;
      const pem = toPEM(certBytes);
      await fs.writeFile(flags['certificate'], pem);
    } else {
      this.error('No certificate found');
    }
  }
}

function toPEM(der: string): string {
  // Split the certificate into lines of 64 characters.
  const lines = der.match(/.{1,64}/g) || '';

  return [`-----BEGIN CERTIFICATE-----`, ...lines, `-----END CERTIFICATE-----`]
    .join('\n')
    .concat('\n');
}
