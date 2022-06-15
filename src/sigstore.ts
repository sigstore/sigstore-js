import { Fulcio } from './fulcio';
import { Rekor } from './rekor';
import { Signer, SignedPayload } from './sign';
import { Verifier } from './verify';
import { pae, Envelope } from './dsse';
import identity, { Provider } from './identity';

export interface SignOptions {
  fulcioBaseURL?: string;
  rekorBaseURL?: string;
  identityToken?: string;
  oidcIssuer?: string;
  oidcClientID?: string;
  oidcClientSecret?: string;
}

export interface VerifierOptions {
  rekorBaseURL?: string;
}

type IdentityProviderOptions = Pick<
  SignOptions,
  'identityToken' | 'oidcIssuer' | 'oidcClientID' | 'oidcClientSecret'
>;

export class Sigstore {
  public async sign(
    payload: Buffer,
    options: SignOptions = {}
  ): Promise<SignedPayload> {
    const fulcio = new Fulcio({ baseURL: options.fulcioBaseURL });
    const rekor = new Rekor({ baseURL: options.rekorBaseURL });
    const idps = this.configureIdentityProviders(options);

    return new Signer({
      fulcio,
      rekor,
      identityProviders: idps,
    }).sign(payload);
  }

  public async signDSSE(
    payload: Buffer,
    payloadType: string,
    options: SignOptions = {}
  ): Promise<Envelope> {
    const paeBuffer = pae(payloadType, payload);
    const signedPayload = await this.sign(paeBuffer, options);

    const envelope: Envelope = {
      payloadType: payloadType,
      payload: payload.toString('base64'),
      signatures: [
        {
          keyid: '',
          sig: signedPayload.base64Signature,
        },
      ],
    };

    return envelope;
  }

  public async verify(
    payload: Buffer,
    signature: string,
    options: VerifierOptions = {}
  ): Promise<boolean> {
    const rekor = new Rekor({ baseURL: options.rekorBaseURL });

    return new Verifier({ rekor }).verify(payload, signature);
  }

  public async verifyDSSE(
    envelope: Envelope,
    options: VerifierOptions = {}
  ): Promise<boolean> {
    const payloadType = envelope.payloadType;
    const payload = Buffer.from(envelope.payload, 'base64');
    const signature = envelope.signatures[0].sig;

    const paeBuffer = pae(payloadType, payload);
    const verified = await this.verify(paeBuffer, signature, options);

    return verified;
  }

  // Translates the IdenityProviderOptions into a list of Providers which
  // should be queried to retrieve an identity token.
  private configureIdentityProviders(
    options: IdentityProviderOptions
  ): Provider[] {
    const idps: Provider[] = [];

    // If an explicit identity token is provided, use that. Setup a dummy
    // provider that just returns the token. Otherwise, setup the CI context
    // provider and (optionally) the OAuth provider.
    if (options.identityToken) {
      idps.push({ getToken: () => Promise.resolve(options.identityToken) });
    } else {
      idps.push(identity.ciContextProvider);
      if (options.oidcIssuer && options.oidcClientID) {
        idps.push(
          identity.oauthProvider(
            options.oidcIssuer,
            options.oidcClientID,
            options.oidcClientSecret
          )
        );
      }
    }

    return idps;
  }
}
