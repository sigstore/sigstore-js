import { Fulcio } from './fulcio';
import { Rekor, Entry } from './rekor';
import { generateKeyPair, hash, signBlob } from './crypto';
import { base64Decode, base64Encode, extractJWTSubject } from './util';
import identity, { Provider } from './identity';

export interface SignOptions {
  fulcio: Fulcio;
  rekor: Rekor;
  oidcIssuer?: string;
  oidcClientID?: string;
  oidcClientSecret?: string;
}

export interface SignedPayload {
  base64Signature: string;
  cert: string;
  bundle?: RekorBundle;
}

export interface RekorBundle {
  signedEntryTimestamp: string;
  payload: RekorPayload;
}

export interface RekorPayload {
  body: object;
  integratedTime: number;
  logIndex: number;
  logID: string;
}

export class Signer {
  private fulcio: Fulcio;
  private rekor: Rekor;

  private identityProviders: Provider[] = [];

  constructor(options: SignOptions) {
    this.fulcio = options.fulcio;
    this.rekor = options.rekor;

    this.identityProviders.push(identity.ciContextProvider);

    if (options.oidcIssuer && options.oidcClientID) {
      this.identityProviders.push(
        identity.oauthProvider(
          options.oidcIssuer,
          options.oidcClientID,
          options.oidcClientSecret
        )
      );
    }
  }

  public async sign(
    payload: Buffer,
    identityToken?: string
  ): Promise<SignedPayload> {
    // Create emphemeral key pair
    const keypair = generateKeyPair();

    // Extract public key as base64-encoded string
    const publicKeyB64 = keypair.publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64');

    // Use excplicitly provided oidc token or try to get one from the identity provider
    identityToken = identityToken || (await this.getIdentityToken());
    if (!identityToken) {
      throw new Error('No identity token provided');
    }

    // Extract challenge claim from OIDC token
    const subject = extractJWTSubject(identityToken);

    // Construct challenge value by encrypting subject with private key
    const challenge = signBlob(keypair.privateKey, subject);

    // Create signing certificate
    const certificate = await this.fulcio.createSigningCertificate({
      identityToken,
      publicKey: publicKeyB64,
      challenge,
    });
    const b64Certificate = base64Encode(certificate);

    // Generate artifact signature
    const signature = signBlob(keypair.privateKey, payload);

    // Calculate artifact digest
    const digest = hash(payload);

    // Create Rekor entry
    const entry = await this.rekor.createEntry({
      artifactDigest: digest,
      artifactSignature: signature,
      certificate: b64Certificate,
    });

    console.error(`Created entry at index ${entry.logIndex}, available at`);
    console.error(
      `https://rekor.sigstore.dev/api/v1/log/entries/${entry.uuid}`
    );

    const signedPayload: SignedPayload = {
      base64Signature: signature,
      cert: b64Certificate,
      bundle: entryToBundle(entry),
    };
    return signedPayload;
  }

  private async getIdentityToken(): Promise<string | undefined> {
    for (const provider of this.identityProviders) {
      const token = await provider.getToken();

      if (token) {
        return token;
      }
    }
  }
}

function entryToBundle(entry: Entry): RekorBundle | undefined {
  if (!entry.verification) {
    return;
  }

  return {
    signedEntryTimestamp: entry.verification.signedEntryTimestamp,
    payload: {
      body: JSON.parse(base64Decode(entry.body)),
      integratedTime: entry.integratedTime,
      logIndex: entry.logIndex,
      logID: entry.logID,
    },
  };
}
