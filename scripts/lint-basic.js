#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const TARGET_DIRS = ['src', 'cli', 'scripts', 'test'];

function collectJsFiles(dir, out = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectJsFiles(fullPath, out);
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.js')) {
      out.push(fullPath);
    }
  }
  return out;
}

const files = [];
for (const dir of TARGET_DIRS) {
  const full = path.join(ROOT, dir);
  if (fs.existsSync(full)) {
    collectJsFiles(full, files);
  }
}

let failed = 0;
const findings = [];

function lineForIndex(text, index) {
  return text.slice(0, index).split('\n').length;
}

function reportFinding(file, line, message) {
  findings.push(`${path.relative(ROOT, file)}:${line} ${message}`);
}

const STATIC_RULES = [
  {
    id: 'no-eval',
    pattern: /\beval\s*\(/g,
    message: 'Avoid eval(); use deterministic parsing/execution paths.',
  },
  {
    id: 'no-new-function',
    pattern: /\bnew\s+Function\s*\(/g,
    message: 'Avoid new Function(); this is dynamic code execution.',
  },
  {
    id: 'no-string-timeout',
    pattern: /\bsetTimeout\s*\(\s*['"`]/g,
    message: 'Avoid string-based setTimeout() (implied eval).',
  },
  {
    id: 'no-string-interval',
    pattern: /\bsetInterval\s*\(\s*['"`]/g,
    message: 'Avoid string-based setInterval() (implied eval).',
  },
  {
    id: 'no-merge-markers',
    pattern: /^(<<<<<<<|=======|>>>>>>>)/gm,
    message: 'Resolve merge conflict markers before commit.',
  },
];

for (const file of files) {
  const source = fs.readFileSync(file, 'utf8');
  const relativePath = path.relative(ROOT, file);

  const result = spawnSync(process.execPath, ['--check', file], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    failed += 1;
    process.stderr.write(result.stderr || result.stdout || `Syntax check failed: ${file}\n`);
  }

  for (const rule of STATIC_RULES) {
    if (path.resolve(file) === __filename) {
      continue;
    }
    rule.pattern.lastIndex = 0;
    let match;
    while ((match = rule.pattern.exec(source)) !== null) {
      failed += 1;
      reportFinding(file, lineForIndex(source, match.index), rule.message);
    }
  }

  if (
    relativePath.startsWith(`src${path.sep}`) &&
    path.resolve(file) !== path.join(ROOT, 'src', 'utils', 'primitives.js') &&
    /function\s+clampPositiveInt\s*\(/.test(source)
  ) {
    failed += 1;
    reportFinding(file, lineForIndex(source, source.indexOf('function clampPositiveInt')), 'Duplicate clampPositiveInt(); use src/utils/primitives.js.');
  }

  if (
    relativePath.startsWith(`src${path.sep}`) &&
    path.resolve(file) !== path.join(ROOT, 'src', 'utils', 'primitives.js') &&
    /function\s+normalizeMode\s*\(/.test(source)
  ) {
    failed += 1;
    reportFinding(file, lineForIndex(source, source.indexOf('function normalizeMode')), 'Duplicate normalizeMode(); use src/utils/primitives.js.');
  }
}

if (failed > 0) {
  if (findings.length > 0) {
    process.stderr.write(`${findings.join('\n')}\n`);
  }
  process.stderr.write(`lint-basic failed: ${failed} issue(s)\n`);
  process.exit(1);
}

process.stdout.write(`lint-basic passed (${files.length} files)\n`);
