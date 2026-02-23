const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const request = require('supertest');

const { SentinelServer } = require('../../src/server');
const {
  createSentinelHome,
  createBaseConfig,
  startUpstream,
  closeServer,
} = require('./helpers/http-harness');

createSentinelHome('sentinel-home-dp-int-');

describe('differential privacy integration', () => {
  let sentinel;
  let upstream;

  afterEach(async () => {
    if (sentinel) {
      await sentinel.stop();
      sentinel = null;
    }
    if (upstream) {
      await closeServer(upstream.server);
      upstream = null;
    }
  });

  test('privacy simulate command writes advisory report and does not affect request responses', async () => {
    const outPath = path.join(os.tmpdir(), `sentinel-dp-sim-${Date.now()}.json`);
    const fixturePath = path.resolve(__dirname, '../fixtures/privacy/numeric.json');

    const missingConfigPath = `${outPath}.missing.yaml`;
    execFileSync('node', [
      './cli/sentinel.js',
      'privacy',
      'simulate',
      '--in',
      fixturePath,
      '--out',
      outPath,
      '--config',
      missingConfigPath,
    ], {
      cwd: path.resolve(__dirname, '../..'),
      stdio: 'pipe',
    });

    const report = JSON.parse(fs.readFileSync(outPath, 'utf8'));
    expect(report.advisory_only).toBe(true);
    expect(report.input_summary.numeric_values).toBeGreaterThan(0);

    let seenBody = null;
    upstream = await startUpstream((req, res) => {
      try {
        seenBody = JSON.parse(Buffer.from(req.body || '').toString('utf8'));
      } catch {
        seenBody = null;
      }
      res.status(200).json({ ok: true });
    });

    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'monitor',
        runtime: {
          differential_privacy: {
            enabled: true,
            epsilon_budget: 1,
            epsilon_per_call: 0.1,
            sensitivity: 1,
            max_simulation_calls: 100,
            max_vector_length: 1024,
          },
        },
      })
    );

    const server = sentinel.start();
    const payload = { value: 42.5, nested: { a: 1 } };

    const response = await request(server)
      .post('/v1/chat/completions')
      .set('content-type', 'application/json')
      .set('x-sentinel-target', 'custom')
      .set('x-sentinel-custom-url', upstream.url)
      .send(payload);

    expect(response.status).toBe(200);
    expect(seenBody).toEqual(payload);
  });
});
