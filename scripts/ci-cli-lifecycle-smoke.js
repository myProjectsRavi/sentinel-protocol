#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

function runChecked(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed: ${result.stderr || result.stdout || 'unknown error'}`);
  }
  return result.stdout || '';
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

async function waitFor(predicate, timeoutMs, description) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const value = predicate();
    if (value) {
      return value;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`timeout waiting for ${description}`);
}

async function waitForExit(child, timeoutMs = 15000) {
  if (Number.isInteger(child.exitCode)) {
    return child.exitCode;
  }
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // best effort
      }
      reject(new Error('sentinel process did not exit after stop'));
    }, timeoutMs);
    child.once('close', (code) => {
      clearTimeout(timer);
      resolve(code);
    });
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function spawnSentinel(installedBin, args, { cwd, env, output }) {
  const child = spawn(installedBin, args, {
    cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (chunk) => output.push(chunk.toString('utf8')));
  child.stderr.on('data', (chunk) => output.push(chunk.toString('utf8')));
  return child;
}

async function waitForRunning(child, statusPath, output) {
  return waitFor(() => {
    if (Number.isInteger(child.exitCode)) {
      throw new Error(`sentinel exited early with ${child.exitCode}: ${output.join('')}`);
    }
    if (!fs.existsSync(statusPath)) {
      return null;
    }
    const status = readJson(statusPath);
    return status.service_status === 'running' ? status : null;
  }, 90000, 'running status');
}

async function stopAndVerify(installedBin, child, { cwd, env, statusPath, output }) {
  runChecked(installedBin, ['stop'], { cwd, env });
  const exitCode = await waitForExit(child);
  if (exitCode !== 0) {
    throw new Error(`sentinel process exited with ${exitCode}: ${output.join('')}`);
  }

  await waitFor(() => {
    if (!fs.existsSync(statusPath)) {
      return null;
    }
    const status = readJson(statusPath);
    return status.service_status === 'stopped' ? status : null;
  }, 15000, 'stopped status');

  const stoppedStatus = JSON.parse(runChecked(installedBin, ['status', '--json'], { cwd, env }));
  if (stoppedStatus.service_status !== 'stopped') {
    throw new Error(`status --json expected stopped after stop, got ${stoppedStatus.service_status}`);
  }
}

async function main() {
  const root = process.cwd();
  const packageVersion = require(path.join(root, 'package.json')).version;
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-cli-lifecycle-'));
  const sentinelHome = path.join(workDir, 'sentinel-home');
  const appDir = path.join(workDir, 'app');
  fs.mkdirSync(sentinelHome, { recursive: true });
  fs.mkdirSync(appDir, { recursive: true });

  const env = {
    ...process.env,
    HOME: workDir,
    SENTINEL_HOME: sentinelHome,
    NODE_ENV: 'production',
  };

  const packStdout = runChecked('npm', ['pack', '--quiet'], { cwd: root, env });
  const tarball = packStdout.trim().split(/\r?\n/).filter(Boolean).pop();
  if (!tarball) {
    throw new Error('npm pack did not produce a tarball');
  }
  const tarballPath = path.join(root, tarball);

  try {
    runChecked('npm', ['init', '--yes'], { cwd: appDir, env });
    runChecked('npm', ['install', '--no-audit', '--no-fund', tarballPath], { cwd: appDir, env });

    const installedBin = path.join(appDir, 'node_modules', '.bin', 'sentinel');
    if (!fs.existsSync(installedBin)) {
      throw new Error(`installed Sentinel npm bin missing: ${installedBin}`);
    }

    const reportedVersion = runChecked(installedBin, ['--version'], { cwd: appDir, env }).trim();
    if (reportedVersion !== packageVersion) {
      throw new Error(`installed npm bin version mismatch: expected ${packageVersion}, got ${reportedVersion}`);
    }

    const configPath = path.join(sentinelHome, 'sentinel.yaml');
    const statusPath = path.join(sentinelHome, 'status.json');
    const bootstrapArgs = [
      'bootstrap',
      '--config',
      configPath,
      '--profile',
      'minimal',
      '--dashboard',
      '--port',
      '0',
      '--shutdown-timeout-ms',
      '15000',
    ];

    // New-user path: the packaged npm bin must initialize and run with the
    // same one-command bootstrap contract documented for npx users.
    const firstOutput = [];
    const first = spawnSentinel(installedBin, bootstrapArgs, {
      cwd: appDir,
      env,
      output: firstOutput,
    });
    const runningStatus = await waitForRunning(first, statusPath, firstOutput);
    if (!fs.existsSync(configPath)) {
      throw new Error('first bootstrap did not create config');
    }
    if (!Number.isInteger(Number(runningStatus.pid)) || Number(runningStatus.pid) <= 0) {
      throw new Error('bootstrap status did not expose a valid pid');
    }
    await stopAndVerify(installedBin, first, {
      cwd: appDir,
      env,
      statusPath,
      output: firstOutput,
    });

    // Existing-user path: simulate a persisted behavioral customization and a
    // human comment, then rerun the exact same bootstrap command. The current
    // config must drive runtime behavior and must not be rewritten by the
    // initialization profile carried in the command.
    const firstConfig = fs.readFileSync(configPath, 'utf8');
    if (!/^mode:\s*monitor\s*$/m.test(firstConfig)) {
      throw new Error('fresh minimal bootstrap did not persist mode: monitor as expected');
    }
    const customMarker = '# ci-existing-user-config-must-survive\n';
    const customizedConfig = `${firstConfig.replace(/^mode:\s*monitor\s*$/m, 'mode: warn').trimEnd()}\n${customMarker}`;
    fs.writeFileSync(configPath, customizedConfig, 'utf8');

    const secondOutput = [];
    const second = spawnSentinel(installedBin, bootstrapArgs, {
      cwd: appDir,
      env,
      output: secondOutput,
    });
    const secondRunningStatus = await waitForRunning(second, statusPath, secondOutput);

    if (secondRunningStatus.configured_mode !== 'warn') {
      throw new Error(
        `repeat bootstrap ignored persisted runtime mode: expected configured_mode=warn, got ${secondRunningStatus.configured_mode}`
      );
    }

    const duringSecondRun = fs.readFileSync(configPath, 'utf8');
    if (duringSecondRun !== customizedConfig) {
      throw new Error('repeat bootstrap rewrote an existing current-version config');
    }

    await stopAndVerify(installedBin, second, {
      cwd: appDir,
      env,
      statusPath,
      output: secondOutput,
    });

    const afterSecondRun = fs.readFileSync(configPath, 'utf8');
    if (afterSecondRun !== customizedConfig) {
      throw new Error('repeat bootstrap did not preserve existing config after shutdown');
    }

    process.stdout.write(`CLI npm bootstrap/update smoke passed for sentinel-protocol@${packageVersion}.\n`);
  } finally {
    try {
      fs.unlinkSync(tarballPath);
    } catch {
      // best effort cleanup
    }
  }
}

main().catch((error) => {
  process.stderr.write(`CLI lifecycle smoke failed: ${error.message}\n`);
  process.exit(1);
});
