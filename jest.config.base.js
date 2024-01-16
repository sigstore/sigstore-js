module.exports = {
  transform: {
    '^.+\\.ts$': '@swc/jest',
  },
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
};
