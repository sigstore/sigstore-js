/* global afterAll, require */
const nockModule = require('nock');
const nock = 'default' in nockModule ? nockModule.default : nockModule;

// Nock 15 patches process-wide sockets, which outlive each Jest sandbox.
afterAll(() => {
  nock.cleanAll();
  nock.restore();
});
