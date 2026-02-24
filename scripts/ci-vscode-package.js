#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function run() {
  const projectRoot = path.resolve(__dirname, '..');
  const extensionDir = path.join(projectRoot, 'extensions', 'vscode-sentinel');
  const extensionPackagePath = path.join(extensionDir, 'package.json');
  if (!fs.existsSync(extensionPackagePath)) {
    throw new Error(`Extension package manifest not found: ${extensionPackagePath}`);
  }

  const extensionPackage = JSON.parse(fs.readFileSync(extensionPackagePath, 'utf8'));
  const extensionVersion = String(extensionPackage.version || '').trim();
  if (!extensionVersion) {
    throw new Error('Extension version is missing in extensions/vscode-sentinel/package.json');
  }

  const artifactDir = path.join(projectRoot, 'dist');
  fs.mkdirSync(artifactDir, { recursive: true });
  const artifactName = `sentinel-protocol-vscode-${extensionVersion}.vsix`;
  const artifactPath = path.join(artifactDir, artifactName);

  const command = 'npx';
  const args = [
    '--yes',
    '@vscode/vsce@2.29.0',
    'package',
    '--out',
    artifactPath,
  ];

  const result = spawnSync(command, args, {
    cwd: extensionDir,
    stdio: 'inherit',
    env: process.env,
  });
  if (result.status !== 0) {
    throw new Error(`VS Code extension packaging failed with exit code ${result.status || 1}`);
  }

  if (!fs.existsSync(artifactPath)) {
    throw new Error(`Expected VSIX artifact not found: ${artifactPath}`);
  }

  console.log(`VSIX packaged: ${artifactPath}`);
}

try {
  run();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
