/* global afterAll, require */
const nock = require('nock');

// Nock 15 patches process-wide sockets, which outlive each Jest sandbox.
afterAll(() => {
  nock.cleanAll();
  nock.restore();
});
