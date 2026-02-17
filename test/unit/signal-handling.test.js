const { installSignalHandlers } = require('../../src');

describe('signal handling', () => {
  test('installSignalHandlers registers and unregisters handlers', () => {
    const beforeSigint = process.listenerCount('SIGINT');
    const beforeSigterm = process.listenerCount('SIGTERM');

    const cleanup = installSignalHandlers(
      {
        stop: async () => {},
      },
      {
        shutdownTimeoutMs: 1000,
      }
    );

    expect(process.listenerCount('SIGINT')).toBe(beforeSigint + 1);
    expect(process.listenerCount('SIGTERM')).toBe(beforeSigterm + 1);

    cleanup();

    expect(process.listenerCount('SIGINT')).toBe(beforeSigint);
    expect(process.listenerCount('SIGTERM')).toBe(beforeSigterm);
  });
});
