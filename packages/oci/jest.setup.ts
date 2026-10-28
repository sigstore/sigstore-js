// @npmcli/agent snapshots proxy variables at load time, so clear them before
// the network tests import the transport.
const proxyEnvKeys = [
  'HTTPS_PROXY',
  'https_proxy',
  'HTTP_PROXY',
  'http_proxy',
  'PROXY',
  'proxy',
  'NO_PROXY',
  'no_proxy',
];

if (expect.getState().testPath?.endsWith('/network.test.ts')) {
  const savedProxyEnv = Object.fromEntries(
    proxyEnvKeys.map((key) => [key, process.env[key]])
  );
  for (const key of proxyEnvKeys) {
    delete process.env[key];
  }

  afterAll(() => {
    for (const key of proxyEnvKeys) {
      if (savedProxyEnv[key] === undefined) delete process.env[key];
      else process.env[key] = savedProxyEnv[key];
    }
  });
}
