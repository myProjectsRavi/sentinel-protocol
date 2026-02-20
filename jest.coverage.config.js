module.exports = {
  testMatch: ['**/test/unit/**/*.test.js'],
  collectCoverage: true,
  coverageThreshold: {
    global: {
      branches: 50,
      functions: 70,
      lines: 60,
      statements: 60,
    },
  },
};
