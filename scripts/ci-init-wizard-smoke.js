#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const yaml = require('js-yaml');

const { validateConfigShape } = require('../src/config/schema');
const { listRuntimeToggleKeys } = require('../src/config/profiles');

const PROFILES = ['minimal', 'standard', 'paranoid'];
const PROVIDERS = ['openai', 'anthropic', 'ollama'];

function runChecked(cliPath, cwd, env, args) {
  const result = spawnSync('node', [cliPath, ...args], {
    cwd,
    env,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(
      `command failed: node ./cli/sentinel.js ${args.join(' ')}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`
    );
  }
  return result.stdout || '';
}

function loadYaml(filePath) {
  return yaml.load(fs.readFileSync(filePath, 'utf8'));
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function enabledRuntimeEngineCount(config) {
  const runtime = config && typeof config === 'object' ? config.runtime || {} : {};
  const keys = listRuntimeToggleKeys(runtime);
  return keys.filter((key) => runtime[key] && runtime[key].enabled === true).length;
}

function main() {
  const root = process.cwd();
  const cliPath = path.join(root, 'cli/sentinel.js');
  const evidence = [];

  for (const profile of PROFILES) {
    for (const provider of PROVIDERS) {
      const workDir = fs.mkdtempSync(path.join(os.tmpdir(), `sentinel-init-${profile}-${provider}-`));
      const projectDir = path.join(workDir, 'project');
      const sentinelHome = path.join(workDir, 'sentinel-home');
      const configPath = path.join(sentinelHome, 'sentinel.yaml');
      fs.mkdirSync(projectDir, { recursive: true });
      fs.mkdirSync(sentinelHome, { recursive: true });

      const env = {
        ...process.env,
        HOME: workDir,
        SENTINEL_HOME: sentinelHome,
        NODE_ENV: 'production',
      };

      const initStdout = runChecked(cliPath, projectDir, env, [
        'init',
        '--config',
        configPath,
        '--yes',
        '--force',
        '--profile',
        profile,
        '--providers',
        provider,
      ]);

      assert(fs.existsSync(configPath), `config missing for ${profile}/${provider}`);
      const config = loadYaml(configPath);
      validateConfigShape(config);

      const target = config?.runtime?.upstream?.resilience_mesh?.targets?.[provider];
      assert(target && target.enabled === true, `provider target not configured for ${profile}/${provider}`);
      assert(initStdout.includes('Doctor summary:'), `doctor summary missing for ${profile}/${provider}`);

      if (profile === 'minimal') {
        const enabledCount = enabledRuntimeEngineCount(config);
        assert(config.mode === 'monitor', 'minimal profile must set mode=monitor');
        assert(enabledCount === 8, `minimal profile expected 8 runtime engines, got ${enabledCount}`);
        const hardCap = config?.runtime?.cost_efficiency_optimizer?.memory_hard_cap_bytes;
        assert(Number(hardCap) === 512 * 1024 * 1024, `minimal profile hard cap mismatch: ${hardCap}`);
      }

      const secondStdout = runChecked(cliPath, projectDir, env, [
        'init',
        '--config',
        configPath,
        '--yes',
      ]);
      assert(secondStdout.includes('Config already exists'), `idempotent message missing for ${profile}/${provider}`);

      evidence.push({
        profile,
        provider,
        mode: String(config.mode || ''),
        runtime_enabled: enabledRuntimeEngineCount(config),
        has_doctor_summary: initStdout.includes('Doctor summary:'),
        idempotent: secondStdout.includes('Config already exists'),
      });
    }
  }

  process.stdout.write('init-wizard matrix validation passed\n');
  process.stdout.write(`${JSON.stringify({ cases: evidence.length, evidence }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`init-wizard matrix validation failed: ${error.message}\n`);
  process.exit(1);
}
