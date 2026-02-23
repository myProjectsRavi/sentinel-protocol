const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const {
  createSentinelHome,
  createBaseConfig,
} = require('./helpers/http-harness');
createSentinelHome('sentinel-home-aibom-int-bootstrap-');
const { SentinelServer } = require('../../src/server');

describe('aibom export integration', () => {
  let sentinel;
  let sentinelHome;

  beforeEach(() => {
    sentinelHome = createSentinelHome('sentinel-home-aibom-int-');
  });

  afterEach(async () => {
    if (sentinel) {
      await sentinel.stop();
      sentinel = null;
    }
  });

  test('traffic through sentinel yields non-empty aibom providers/models export', () => {
    sentinel = new SentinelServer(createBaseConfig());
    sentinel.aibom.recordRoute({
      provider: 'custom',
      routePlan: {
        routeSource: 'header',
        requestedTarget: 'custom',
      },
    });
    sentinel.aibom.recordRequest({
      provider: 'custom',
      headers: {
        'x-sentinel-agent-id': 'agent-aibom-int',
      },
      body: {
        model: 'gpt-4o-mini',
        tools: [{ function: { name: 'search_docs' } }],
        dataset_id: 'tenant_dataset_alpha',
      },
    });
    sentinel.aibom.recordResponse({
      provider: 'custom',
      headers: {
        'x-openai-model': 'gpt-4o-mini',
      },
      body: {
        id: 'resp-1',
        data_source: {
          source_url: 'https://datasets.internal.local/tenant_dataset_alpha',
        },
      },
    });

    const aibom = sentinel.currentStatusPayload().aibom;
    expect(aibom.totals.providers).toBeGreaterThan(0);
    expect(aibom.totals.models).toBeGreaterThan(0);
    expect(aibom.totals.datasets).toBeGreaterThan(0);
  });

  test('aibom export command writes valid json artifact', () => {
    sentinel = new SentinelServer(createBaseConfig());
    sentinel.aibom.recordRoute({
      provider: 'openai',
      routePlan: {
        routeSource: 'header',
        requestedTarget: 'openai',
      },
    });
    sentinel.aibom.recordRequest({
      provider: 'openai',
      body: {
        model: 'gpt-4o-mini',
      },
      headers: {
        'x-sentinel-agent-id': 'agent-aibom-cli',
      },
    });
    sentinel.writeStatus();

    const outPath = path.join(sentinelHome, 'aibom.json');
    const result = spawnSync(
      process.execPath,
      [path.resolve(__dirname, '../../cli/sentinel.js'), 'aibom', 'export', '--format', 'json', '--out', outPath],
      {
        cwd: path.resolve(__dirname, '../..'),
        env: {
          ...process.env,
          SENTINEL_HOME: sentinelHome,
        },
        encoding: 'utf8',
      }
    );

    expect(result.status).toBe(0);
    expect(fs.existsSync(outPath)).toBe(true);
    const payload = JSON.parse(fs.readFileSync(outPath, 'utf8'));
    expect(payload.schema_version).toBe('sentinel.aibom.v1');
    expect(Array.isArray(payload.providers)).toBe(true);
    expect(Array.isArray(payload.models)).toBe(true);
    expect(Array.isArray(payload.datasets)).toBe(true);
  });
});
