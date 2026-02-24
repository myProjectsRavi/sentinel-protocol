#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const { InjectionScanner } = require('../../../src/engines/injection-scanner');
const { AdversarialEvalHarness, DEFAULT_CASES } = require('../../../src/governance/adversarial-eval-harness');

function getInput(name, fallback = '') {
  const key = `INPUT_${String(name || '').replace(/ /g, '_').replace(/-/g, '_').toUpperCase()}`;
  const value = process.env[key];
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  return String(value);
}

function toBoolean(value, fallback = false) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized) {
    return fallback;
  }
  if (['1', 'true', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'off'].includes(normalized)) {
    return false;
  }
  return fallback;
}

function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeCasesFromFile(filePath) {
  if (!filePath || !fs.existsSync(filePath)) {
    return null;
  }
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (parsed && Array.isArray(parsed.cases)) {
    return parsed.cases;
  }
  return null;
}

function writeGithubOutput(values) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) {
    return;
  }
  const lines = Object.entries(values).map(([key, value]) => `${key}=${value}`);
  fs.appendFileSync(outputPath, `${lines.join('\n')}\n`, 'utf8');
}

function appendStepSummary(lines) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    return;
  }
  fs.appendFileSync(summaryPath, `${lines.join('\n')}\n`, 'utf8');
}

function buildSarif(report) {
  const results = [];
  for (const item of report.results || []) {
    const expected = item.expected_detection === true;
    const missed = expected && item.detected !== true;
    const falsePositive = expected !== true && item.detected === true;
    if (!missed && !falsePositive) {
      continue;
    }
    results.push({
      ruleId: missed ? 'SENTINEL_MISSED_DETECTION' : 'SENTINEL_FALSE_POSITIVE',
      level: missed ? 'error' : 'warning',
      message: {
        text: missed
          ? `Missed expected detection for case ${item.id} (${item.family})`
          : `False positive for benign case ${item.id} (${item.family})`,
      },
      properties: {
        case_id: item.id,
        family: item.family,
        engines: Array.isArray(item.engines) ? item.engines : [],
      },
    });
  }

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'sentinel-protocol/security-scan',
            rules: [
              {
                id: 'SENTINEL_MISSED_DETECTION',
                shortDescription: { text: 'Missed expected adversarial detection' },
              },
              {
                id: 'SENTINEL_FALSE_POSITIVE',
                shortDescription: { text: 'False positive on benign adversarial case' },
              },
            ],
          },
        },
        results,
      },
    ],
  };
}

function readPullRequestNumber() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !fs.existsSync(eventPath)) {
    return null;
  }
  try {
    const payload = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
    return payload?.pull_request?.number || null;
  } catch {
    return null;
  }
}

async function postPrComment(body) {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
  const repo = process.env.GITHUB_REPOSITORY || '';
  const [owner, name] = repo.split('/');
  const pullNumber = readPullRequestNumber();
  if (!token || !owner || !name || !pullNumber) {
    return false;
  }
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${name}/issues/${pullNumber}/comments`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ body }),
    }
  );
  return response.ok;
}

function markdownSummary(report, threshold) {
  const summary = report.summary || {};
  const detectionRate = Number(summary.detection_rate || 0);
  const regressionDetected = summary.regression_detected === true;
  const pass = detectionRate >= threshold && !regressionDetected;
  return [
    '### Sentinel Security Scan',
    '',
    `- Detection rate: **${(detectionRate * 100).toFixed(2)}%** (threshold ${(threshold * 100).toFixed(2)}%)`,
    `- Missed detections: **${summary.missed_detections || 0}**`,
    `- False positives: **${summary.false_positives || 0}**`,
    `- Regression detected: **${regressionDetected ? 'yes' : 'no'}**`,
    `- Result: **${pass ? 'pass' : 'fail'}**`,
    '',
    '<details><summary>Case-by-case results</summary>',
    '',
    '| Case | Family | Expected | Detected | Engines |',
    '|---|---|---:|---:|---|',
    ...(report.results || []).map((item) => {
      const engines = Array.isArray(item.engines) && item.engines.length > 0 ? item.engines.join(', ') : '-';
      return `| ${item.id} | ${item.family} | ${item.expected_detection ? 'yes' : 'no'} | ${
        item.detected ? 'yes' : 'no'
      } | ${engines} |`;
    }),
    '',
    '</details>',
  ].join('\n');
}

async function main() {
  const threshold = Math.max(0, Math.min(1, toNumber(getInput('threshold', '0.85'), 0.85)));
  const failOnRegression = toBoolean(getInput('fail-on-regression', 'true'), true);
  const postComment = toBoolean(getInput('post-comment', 'true'), true);
  const sarifOutput = String(getInput('sarif-output', '') || '').trim();
  const evalFileInput = String(getInput('eval-file', 'sentinel-eval.json') || '').trim();
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const evalFilePath = path.isAbsolute(evalFileInput) ? evalFileInput : path.join(workspace, evalFileInput);

  const customCases = normalizeCasesFromFile(evalFilePath);
  const scanner = new InjectionScanner({
    maxScanBytes: 131072,
  });
  const harness = new AdversarialEvalHarness({
    enabled: true,
    regression_drop_threshold: 0.1,
    max_cases: 2000,
  });

  const run = harness.run({
    cases: customCases || DEFAULT_CASES,
    adapters: {
      injectionScan: (text) => {
        const outcome = scanner.scan(String(text || ''));
        return {
          detected: Number(outcome.score || 0) >= 0.5,
          score: Number(outcome.score || 0),
        };
      },
    },
    runId: process.env.GITHUB_RUN_ID ? `gh-${process.env.GITHUB_RUN_ID}` : undefined,
  });

  if (!run?.report) {
    throw new Error('Adversarial eval harness returned no report.');
  }

  const report = run.report;
  const summary = report.summary || {};
  const detectionRate = Number(summary.detection_rate || 0);
  const regressionDetected = summary.regression_detected === true;
  const belowThreshold = detectionRate < threshold;
  const shouldFail = belowThreshold || (failOnRegression && regressionDetected);

  const markdown = markdownSummary(report, threshold);
  appendStepSummary([markdown]);
  console.log(markdown);

  if (sarifOutput) {
    const sarifPath = path.isAbsolute(sarifOutput) ? sarifOutput : path.join(workspace, sarifOutput);
    fs.writeFileSync(sarifPath, `${JSON.stringify(buildSarif(report), null, 2)}\n`, 'utf8');
    console.log(`SARIF written: ${sarifPath}`);
  }

  writeGithubOutput({
    detection_rate: detectionRate.toFixed(6),
    missed_detections: String(summary.missed_detections || 0),
    false_positives: String(summary.false_positives || 0),
    regression_detected: regressionDetected ? 'true' : 'false',
    pass: shouldFail ? 'false' : 'true',
  });

  const findingsExist = Number(summary.missed_detections || 0) > 0 || Number(summary.false_positives || 0) > 0;
  if (postComment && (findingsExist || regressionDetected || shouldFail)) {
    const posted = await postPrComment(markdown);
    if (posted) {
      console.log('Posted Sentinel security scan comment to pull request.');
    } else {
      console.log('Skipped PR comment (no token/event context or API request failed).');
    }
  }

  if (shouldFail) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(`sentinel security-scan action failed: ${error.message}`);
  process.exitCode = 1;
});

