const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

function waitForStart(child, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Timed out waiting for Sentinel startup log'));
    }, timeoutMs);

    const onData = (chunk) => {
      const text = String(chunk);
      if (text.includes('"message":"Sentinel started"')) {
        clearTimeout(timer);
        child.stdout.off('data', onData);
        resolve();
      }
    };

    child.stdout.on('data', onData);
    child.once('exit', (code) => {
      clearTimeout(timer);
      child.stdout.off('data', onData);
      reject(new Error(`Sentinel exited before startup (code ${code})`));
    });
  });
}

describe('signal shutdown', () => {
  test('start command handles SIGTERM gracefully and exits cleanly', async () => {
    const sentinelHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-signal-home-'));
    const cwd = path.join(__dirname, '..', '..');
    const child = spawn(
      process.execPath,
      ['./cli/sentinel.js', 'start', '--config', './src/config/default.yaml', '--port', '0', '--skip-doctor'],
      {
        cwd,
        env: {
          ...process.env,
          NODE_ENV: 'production',
          SENTINEL_HOME: sentinelHome,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      }
    );

    let stderr = '';
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });

    try {
      await waitForStart(child);

      const exitPromise = new Promise((resolve) => {
        child.once('exit', (code, signal) => resolve({ code, signal }));
      });

      child.kill('SIGTERM');
      const exited = await exitPromise;

      expect(exited.code).toBe(0);
      expect(stderr).toContain('Received SIGTERM, shutting down...');
    } finally {
      if (!child.killed) {
        child.kill('SIGKILL');
      }
      fs.rmSync(sentinelHome, { recursive: true, force: true });
    }
  });
});
