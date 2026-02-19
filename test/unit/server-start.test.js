const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.SENTINEL_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-home-server-start-'));

const { loadAndValidateConfig } = require('../../src/config/loader');
const { SentinelServer } = require('../../src/server');

const PROJECT_DEFAULT_CONFIG = path.join(__dirname, '..', '..', 'src', 'config', 'default.yaml');

describe('SentinelServer start', () => {
  test('respects numeric port override 0 instead of falling back to config port', async () => {
    const loaded = loadAndValidateConfig({
      configPath: PROJECT_DEFAULT_CONFIG,
      allowMigration: false,
      writeMigrated: false,
    });

    const sentinel = new SentinelServer(loaded.config, { portOverride: 0 });
    const fakeServer = {
      close(callback) {
        if (typeof callback === 'function') {
          callback();
        }
      },
    };

    const listenMock = jest.fn((port, host, onListening) => {
      if (typeof onListening === 'function') {
        onListening();
      }
      return fakeServer;
    });
    sentinel.app.listen = listenMock;

    sentinel.start();

    expect(listenMock).toHaveBeenCalledWith(0, loaded.config.proxy.host, expect.any(Function));

    await sentinel.stop();
  });
});
