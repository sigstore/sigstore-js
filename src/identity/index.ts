import { default as providers } from './provider';
import { GHAProvider } from './gha';
import { OAuthProvider } from './oauth';
import { Issuer } from './issuer';

// Register GitHub Actions provider
providers.add(new GHAProvider());

// Register Sigstore OAuth provider
const sigstoreOAuthIssuer = new Issuer('https://oauth2.sigstore.dev/auth');
providers.add(new OAuthProvider('sigstore', '', sigstoreOAuthIssuer));

export async function getToken(): Promise<string | undefined> {
  for (const p of providers.all()) {
    const token = await p.getToken();

    if (token) {
      return token;
    }
  }
}
