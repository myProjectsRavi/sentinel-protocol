#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { detectFramework } = require('../src/cli/adoption');

const CASES = [
  { expected: 'express', deps: { express: '^4.22.0' } },
  { expected: 'fastify', deps: { fastify: '^4.28.0' } },
  { expected: 'nextjs', deps: { next: '^15.0.0' } },
  { expected: 'koa', deps: { koa: '^2.15.0' } },
  { expected: 'hono', deps: { '@hono/node-server': '^1.13.0' } },
  { expected: 'nestjs', deps: { '@nestjs/core': '^10.4.0', '@nestjs/common': '^10.4.0' } },
  { expected: null, deps: {} },
];

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function runInit(root, projectDir, env, configPath) {
  const result = spawnSync('node', [path.join(root, 'cli/sentinel.js'), 'init', '--config', configPath, '--yes', '--force', '--profile', 'minimal'], {
    cwd: projectDir,
    env,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(`sentinel init failed:\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  }
  return result.stdout || '';
}

function main() {
  const root = process.cwd();
  const evidence = [];

  for (const testCase of CASES) {
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-framework-detect-'));
    const projectDir = path.join(workDir, 'project');
    const sentinelHome = path.join(workDir, 'sentinel-home');
    const configPath = path.join(sentinelHome, 'sentinel.yaml');
    fs.mkdirSync(projectDir, { recursive: true });
    fs.mkdirSync(sentinelHome, { recursive: true });

    fs.writeFileSync(
      path.join(projectDir, 'package.json'),
      `${JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: testCase.deps }, null, 2)}\n`,
      'utf8'
    );

    const env = {
      ...process.env,
      HOME: workDir,
      SENTINEL_HOME: sentinelHome,
      NODE_ENV: 'production',
    };

    const detected = detectFramework(projectDir);
    assert(detected === testCase.expected, `detectFramework mismatch; expected=${testCase.expected} got=${detected}`);

    const stdout = runInit(root, projectDir, env, configPath);
    const configText = fs.readFileSync(configPath, 'utf8');

    if (testCase.expected) {
      assert(stdout.includes(`Detected framework: ${testCase.expected}`), `missing detection stdout for ${testCase.expected}`);
      assert(stdout.includes("const { createSentinel } = require('sentinel-protocol');"), `missing embed snippet for ${testCase.expected}`);
      assert(stdout.includes("baseURL: 'http://127.0.0.1:8787/v1'"), `missing proxy baseURL snippet for ${testCase.expected}`);
      assert(configText.includes(`# Framework detected: ${testCase.expected}`), `missing framework hint block for ${testCase.expected}`);
    } else {
      assert(!stdout.includes('Detected framework:'), 'unexpected framework detection for no-framework fixture');
      assert(configText.includes('# Framework detected: none'), 'expected none framework hint block');
    }

    evidence.push({
      expected: testCase.expected || 'none',
      detected: detected || 'none',
      printed: testCase.expected ? stdout.includes(`Detected framework: ${testCase.expected}`) : true,
    });
  }

  process.stdout.write('framework detection smoke passed\n');
  process.stdout.write(`${JSON.stringify({ cases: evidence.length, evidence }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`framework detection smoke failed: ${error.message}\n`);
  process.exit(1);
}
