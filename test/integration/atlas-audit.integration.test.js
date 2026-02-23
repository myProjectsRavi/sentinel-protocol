const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const {
  createSentinelHome,
  createBaseConfig,
} = require('./helpers/http-harness');
createSentinelHome('sentinel-home-atlas-int-bootstrap-');
const { SentinelServer } = require('../../src/server');

function readJsonLines(filePath) {
  if (!fs.existsSync(filePath)) {
    return [];
  }
  return fs
    .readFileSync(filePath, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

describe('atlas audit integration', () => {
  let sentinel;
  let sentinelHome;

  beforeEach(() => {
    sentinelHome = createSentinelHome('sentinel-home-atlas-int-');
  });

  afterEach(async () => {
    if (sentinel) {
      await sentinel.stop();
      sentinel = null;
    }
  });

  test('audit records include atlas enrichment fields for blocked injection event', async () => {
    sentinel = new SentinelServer(
      createBaseConfig({
        mode: 'enforce',
        rules: [
          {
            name: 'block-injection',
            match: {
              method: 'POST',
              injection_threshold: 0.8,
            },
            action: 'block',
            message: 'Prompt injection detected',
          },
        ],
      })
    );
    await sentinel.auditLogger.write({
      timestamp: new Date().toISOString(),
      decision: 'blocked_policy',
      reasons: ['prompt_injection_detected', 'injection:high'],
      provider: 'openai',
      response_status: 403,
      correlation_id: 'atlas-int-test',
    });

    const auditPath = sentinel.auditLogger.filePath;
    await sentinel.stop();
    sentinel = null;

    const events = readJsonLines(auditPath);
    expect(events.length).toBeGreaterThan(0);
    const blocked = events.find((event) => String(event.decision || '').startsWith('blocked'));
    expect(blocked).toBeDefined();
    expect(blocked.atlas).toBeDefined();
    expect(blocked.atlas.technique_id).toBeTruthy();
    expect(blocked.atlas.tactic).toBeTruthy();
    expect(blocked.atlas.name).toBeTruthy();
    expect(blocked.atlas.severity).toBeTruthy();
  });

  test('atlas report command writes json with expected schema', () => {
    const auditPath = path.join(sentinelHome, 'audit.jsonl');
    const outPath = path.join(sentinelHome, 'atlas-report.json');
    fs.writeFileSync(
      auditPath,
      [
        JSON.stringify({ decision: 'blocked_policy', engine: 'injection_scanner' }),
        JSON.stringify({ decision: 'forwarded', engine: 'pii_scanner' }),
      ].join('\n') + '\n',
      'utf8'
    );

    const result = spawnSync(
      process.execPath,
      [path.resolve(__dirname, '../../cli/sentinel.js'), 'atlas', 'report', '--audit-path', auditPath, '--out', outPath],
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
    const report = JSON.parse(fs.readFileSync(outPath, 'utf8'));
    expect(report.schema_version).toBe('sentinel.atlas.navigator.v1');
    expect(typeof report.mapping_version).toBe('string');
    expect(Array.isArray(report.techniques)).toBe(true);
    expect(report.summary).toBeDefined();
    expect(Array.isArray(report.summary.top_techniques)).toBe(true);
  });
});
