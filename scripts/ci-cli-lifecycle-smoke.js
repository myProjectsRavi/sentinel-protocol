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
      reject(new Error('sentinel start process did not exit after stop'));
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

async function main() {
  const root = process.cwd();
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

    const installedCli = path.join(appDir, 'node_modules', 'sentinel-protocol', 'cli', 'sentinel.js');
    if (!fs.existsSync(installedCli)) {
      throw new Error(`installed Sentinel CLI missing: ${installedCli}`);
    }

    const configPath = path.join(sentinelHome, 'sentinel.yaml');
    runChecked(process.execPath, [installedCli, 'init', '--config', configPath, '--force', '--yes', '--profile', 'minimal'], {
      cwd: appDir,
      env,
    });
    if (!fs.existsSync(configPath)) {
      throw new Error('sentinel init did not create config');
    }

    const output = [];
    const child = spawn(
      process.execPath,
      [installedCli, 'start', '--config', configPath, '--dry-run', '--skip-doctor', '--port', '0'],
      {
        cwd: appDir,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      }
    );
    child.stdout.on('data', (chunk) => output.push(chunk.toString('utf8')));
    child.stderr.on('data', (chunk) => output.push(chunk.toString('utf8')));

    const statusPath = path.join(sentinelHome, 'status.json');
    await waitFor(() => {
      if (Number.isInteger(child.exitCode)) {
        throw new Error(`sentinel start exited early with ${child.exitCode}: ${output.join('')}`);
      }
      if (!fs.existsSync(statusPath)) {
        return null;
      }
      const status = readJson(statusPath);
      return status.service_status === 'running' ? status : null;
    }, 90000, 'running status');

    const statusStdout = runChecked(process.execPath, [installedCli, 'status', '--json'], { cwd: appDir, env });
    const runningStatus = JSON.parse(statusStdout);
    if (runningStatus.service_status !== 'running') {
      throw new Error(`status --json expected running, got ${runningStatus.service_status}`);
    }
    if (runningStatus.effective_mode !== 'monitor') {
      throw new Error(`dry-run expected effective_mode=monitor, got ${runningStatus.effective_mode}`);
    }
    if (!Number.isInteger(Number(runningStatus.pid)) || Number(runningStatus.pid) <= 0) {
      throw new Error('status --json did not expose a valid pid');
    }

    runChecked(process.execPath, [installedCli, 'stop'], { cwd: appDir, env });
    const exitCode = await waitForExit(child);
    if (exitCode !== 0) {
      throw new Error(`sentinel start process exited with ${exitCode}: ${output.join('')}`);
    }

    await waitFor(() => {
      if (!fs.existsSync(statusPath)) {
        return null;
      }
      const status = readJson(statusPath);
      return status.service_status === 'stopped' ? status : null;
    }, 15000, 'stopped status');

    const stoppedStdout = runChecked(process.execPath, [installedCli, 'status', '--json'], { cwd: appDir, env });
    const stoppedStatus = JSON.parse(stoppedStdout);
    if (stoppedStatus.service_status !== 'stopped') {
      throw new Error(`status --json expected stopped after stop, got ${stoppedStatus.service_status}`);
    }

    process.stdout.write('CLI lifecycle smoke passed.\n');
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
