module.exports = {
  transform: {
    '^.+\\.(t|[cm]?j)s$': [
      '@swc/jest',
      {
        jsc: {
          target: "es2021",
        },
      },
    ],
  },
  transformIgnorePatterns: [
    'node_modules/(?!(agent-base|http-proxy-agent|https-proxy-agent|socks-proxy-agent|socks|openid-client|oauth4webapi|jose|asn1js|pkijs|bytestreamjs|@peculiar/(utils|webcrypto|x509|asn1-[^/]+|json-schema)|webcrypto-core|@noble/hashes|canonicalize|@tufjs/repo-mock|nock|@mswjs/interceptors|@open-draft/until|rettime)/)',
  ],
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
};
