module.exports = {
  transform: {
    '^.+\\.(t|j)s$': [
      '@swc/jest',
      {
        jsc: {
          target: "es2021",
        },
      },
    ],
  },
  transformIgnorePatterns: [
    'node_modules/(?!(agent-base|http-proxy-agent|https-proxy-agent|socks-proxy-agent|socks|asn1js|pkijs|bytestreamjs|@peculiar/(utils|webcrypto|x509|asn1-[^/]+|json-schema)|webcrypto-core|@noble/hashes|canonicalize)/)',
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
