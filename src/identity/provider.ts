// Interface representing any identity provider which is capable of returning
// an OIDC token.
export interface Provider {
  getToken: () => Promise<string | undefined>;
}

const registeredProviders: Provider[] = [];

// Register a new provider
function add(provider: Provider): void {
  registeredProviders.push(provider);
}

// Returns a list of all registered providers
function all(): Provider[] {
  return Array.from(registeredProviders);
}

export default { add, all };
