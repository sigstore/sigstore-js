// Interface representing any identity provider which is capable of returning
// an OIDC token.
export interface Provider {
  getToken: () => Promise<string | undefined>;
}
