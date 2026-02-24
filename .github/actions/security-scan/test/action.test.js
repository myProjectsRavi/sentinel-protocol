/* eslint-env jest */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ACTION_ENTRY = path.join(__dirname, '..', 'index.js');

function runAction(envOverrides = {}) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-action-test-'));
  const outputFile = path.join(temp, 'gh-output.txt');
  const summaryFile = path.join(temp, 'gh-summary.md');
  const workspace = path.join(temp, 'workspace');
  fs.mkdirSync(workspace, { recursive: true });

  const env = {
    ...process.env,
    GITHUB_OUTPUT: outputFile,
    GITHUB_STEP_SUMMARY: summaryFile,
    GITHUB_WORKSPACE: workspace,
    INPUT_POST_COMMENT: 'false',
    ...envOverrides,
  };

  const result = spawnSync('node', [ACTION_ENTRY], {
    env,
    encoding: 'utf8',
  });

  return {
    temp,
    workspace,
    outputFile,
    summaryFile,
    result,
  };
}

describe('security-scan action', () => {
  test('writes outputs and optional SARIF artifact', () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-action-pass-'));
    const sarifPath = path.join(temp, 'scan.sarif');
    const run = runAction({
      INPUT_THRESHOLD: '0.85',
      INPUT_SARIF_OUTPUT: sarifPath,
    });

    expect(run.result.status).toBe(0);
    const out = fs.readFileSync(run.outputFile, 'utf8');
    expect(out.includes('detection_rate=')).toBe(true);
    expect(out.includes('pass=true')).toBe(true);
    expect(out.includes('detection_rate=1.000000')).toBe(true);
    const summary = fs.readFileSync(run.summaryFile, 'utf8');
    expect(summary.includes('### Sentinel Security Scan')).toBe(true);
    expect(summary.includes('tool_forgery_heuristic')).toBe(true);
    expect(fs.existsSync(sarifPath)).toBe(true);
  });

  test('fails when detection rate is below threshold', () => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-action-fail-'));
    const workspace = path.join(temp, 'workspace');
    const outputFile = path.join(temp, 'gh-output.txt');
    const summaryFile = path.join(temp, 'gh-summary.md');
    fs.mkdirSync(workspace, { recursive: true });
    const evalFile = path.join(workspace, 'sentinel-eval.json');
    fs.writeFileSync(
      evalFile,
      `${JSON.stringify({ cases: [{ id: 'forced_miss', family: 'prompt_injection', prompt: 'hello world', expected_detection: true }] }, null, 2)}\n`,
      'utf8'
    );

    const rerun = spawnSync('node', [ACTION_ENTRY], {
      env: {
        ...process.env,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        GITHUB_WORKSPACE: workspace,
        INPUT_THRESHOLD: '0.90',
        INPUT_EVAL_FILE: 'sentinel-eval.json',
        INPUT_POST_COMMENT: 'false',
      },
      encoding: 'utf8',
    });

    expect(rerun.status).toBe(1);
    const out = fs.readFileSync(outputFile, 'utf8');
    expect(out.includes('pass=false')).toBe(true);
  });
});
