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

function readJsonIfExists(filePath) {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

async function waitForServerReady(statusPath, timeoutMs = 25000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const payload = readJsonIfExists(statusPath);
    if (payload?.service_status === 'running') {
      return payload;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('sentinel start timeout waiting for running status');
}

function killSpawnedProcess(child, signal) {
  if (!child || !Number.isInteger(child.pid)) {
    return;
  }
  // When detached, negative PID targets the process group and cleans up npx+sentinel.
  try {
    process.kill(-child.pid, signal);
    return;
  } catch {
    // fall through to direct child signal
  }
  try {
    child.kill(signal);
  } catch {
    // best-effort cleanup
  }
}

async function terminateSpawnedProcess(child, output) {
  if (!child || !Number.isInteger(child.pid)) {
    return { code: 0, signal: null };
  }

  killSpawnedProcess(child, 'SIGTERM');
  return await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(graceTimer);
      clearTimeout(forceTimer);
      resolve(result);
    };
    const fail = (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(graceTimer);
      clearTimeout(forceTimer);
      reject(error);
    };

    const onClose = (code, signal) => finish({ code, signal });
    const onError = (error) => fail(error);
    child.once('close', onClose);
    child.once('error', onError);

    const graceTimer = setTimeout(() => {
      killSpawnedProcess(child, 'SIGKILL');
    }, 8000);
    graceTimer.unref?.();

    const forceTimer = setTimeout(() => {
      fail(new Error(`sentinel start process did not terminate after SIGTERM/SIGKILL\n${output.join('')}`));
    }, 12000);
    forceTimer.unref?.();
  });
}

async function main() {
  const root = process.cwd();
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-npx-bootstrap-'));
  const sentinelHome = path.join(workDir, 'sentinel-home');
  fs.mkdirSync(sentinelHome, { recursive: true });

  const env = {
    ...process.env,
    HOME: workDir,
    SENTINEL_HOME: sentinelHome,
    NODE_ENV: 'production',
  };

  const packStdout = runChecked('npm', ['pack', '--quiet'], {
    cwd: root,
    env,
  });
  const tarball = packStdout
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .pop();
  if (!tarball) {
    throw new Error('npm pack did not produce a tarball name');
  }
  const tarballPath = path.join(root, tarball);
  if (!fs.existsSync(tarballPath)) {
    throw new Error(`npm pack tarball missing: ${tarballPath}`);
  }

  try {
    runChecked('npx', ['--yes', '--package', tarballPath, 'sentinel', 'init', '--force'], {
      cwd: root,
      env,
    });
    const configPath = path.join(sentinelHome, 'sentinel.yaml');
    if (!fs.existsSync(configPath)) {
      throw new Error(`expected config not created: ${configPath}`);
    }

    const child = spawn(
      'npx',
      ['--yes', '--package', tarballPath, 'sentinel', 'start', '--config', configPath, '--port', '0', '--skip-doctor'],
      {
        cwd: root,
        env,
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      }
    );

    const output = [];
    child.stdout.on('data', (chunk) => output.push(chunk.toString('utf8')));
    child.stderr.on('data', (chunk) => output.push(chunk.toString('utf8')));

    const statusPath = path.join(sentinelHome, 'status.json');
    await waitForServerReady(statusPath);

    await terminateSpawnedProcess(child, output);
    process.stdout.write('npx bootstrap validation passed.\n');
  } finally {
    try {
      fs.unlinkSync(tarballPath);
    } catch {
      // best-effort cleanup
    }
  }
}

main().catch((error) => {
  process.stderr.write(`npx bootstrap validation failed: ${error.message}\n`);
  process.exit(1);
});
