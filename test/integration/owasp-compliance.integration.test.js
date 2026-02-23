const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { createSentinelHome } = require('./helpers/http-harness');

describe('owasp compliance integration', () => {
  let sentinelHome;

  beforeEach(() => {
    sentinelHome = createSentinelHome('sentinel-home-owasp-int-');
  });

  test('cli compliance owasp-llm writes report with expected metadata', () => {
    const configPath = path.join(sentinelHome, 'sentinel.yaml');
    const outPath = path.join(sentinelHome, 'owasp-llm-report.html');
    const defaultConfigPath = path.resolve(__dirname, '../../src/config/default.yaml');
    fs.copyFileSync(defaultConfigPath, configPath);

    const result = spawnSync(
      process.execPath,
      [
        path.resolve(__dirname, '../../cli/sentinel.js'),
        'compliance',
        'owasp-llm',
        '--config',
        configPath,
        '--report',
        'html',
        '--out',
        outPath,
      ],
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
    const html = fs.readFileSync(outPath, 'utf8');
    expect(html.includes('Sentinel OWASP LLM Top 10 Compliance Report')).toBe(true);
    expect(html.includes('schema_version=sentinel.owasp.llm-top10.v1')).toBe(true);
    expect(html.includes('raw_payloads_exposed=false')).toBe(true);
  });
});
