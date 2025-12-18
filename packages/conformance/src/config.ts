export const STAGING_SIGNING_CONFIG = {
  mediaType: 'application/vnd.dev.sigstore.signingconfig.v0.2+json',
  caUrls: [
    {
      url: 'https://fulcio.sigstage.dev',
      majorApiVersion: 1,
      validFor: { start: '2022-04-13T20:06:15.000Z' },
    },
  ],
  rekorTlogUrls: [
    {
      url: 'https://rekor.sigstage.dev',
      majorApiVersion: 1,
      validFor: { start: '2021-01-12T11:53:27.000Z' },
    },
  ],
  rekorTlogConfig: {
    selector: 'ANY',
  },
};

export const PRODUCTION_SIGNING_CONFIG = {
  mediaType: 'application/vnd.dev.sigstore.signingconfig.v0.2+json',
  caUrls: [
    {
      url: 'https://fulcio.sigstore.dev',
      majorApiVersion: 1,
      validFor: { start: '2022-04-13T20:06:15.000Z' },
    },
  ],
  rekorTlogUrls: [
    {
      url: 'https://rekor.sigstore.dev',
      majorApiVersion: 1,
      validFor: { start: '2021-01-12T11:53:27.000Z' },
    },
  ],
  rekorTlogConfig: {
    selector: 'ANY',
  },
};
