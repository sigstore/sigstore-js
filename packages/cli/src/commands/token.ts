import { Command, Flags } from '@oclif/core';
import { OAuthIdentityProvider } from '../oauth';

export default class Token extends Command {
  static override description = 'retrieve an OIDC token';
  static override examples = ['<%= config.bin %> <%= command.id %>'];
  static override hidden = true;

  static override flags = {
    issuer: Flags.string({
      description: 'OIDC provider to be used to issue ID token',
      default: 'https://oauth2.sigstore.dev/auth',
      required: true,
    }),
    'client-id': Flags.string({
      description: 'OIDC client ID',
      default: 'sigstore',
      required: true,
    }),
    'client-secret': Flags.string({
      description: 'OIDC client secret',
      required: false,
    }),
    'redirect-url': Flags.string({
      description: 'OIDC redirect URL',
      required: false,
      env: 'OIDC_REDIRECT_URL',
    }),
  };

  public async run(): Promise<void> {
    const { flags } = await this.parse(Token);

    const provider = new OAuthIdentityProvider({
      issuer: flags.issuer,
      clientID: flags['client-id'],
      clientSecret: flags['client-secret'],
      redirectURL: flags['redirect-url'],
    });

    const idToken = await provider.getToken();
    this.log(idToken);
  }
}
