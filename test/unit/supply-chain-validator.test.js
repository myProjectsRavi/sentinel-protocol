const fs = require('fs');
const os = require('os');
const path = require('path');

const { SupplyChainValidator } = require('../../src/security/supply-chain-validator');

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2), 'utf8');
}

describe('SupplyChainValidator', () => {
  test('blocks when blocked package is present and block mode is enforced', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-supply-chain-'));
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'tmp-project',
      version: '1.0.0',
      dependencies: {
        'left-pad': '1.3.0',
      },
    });

    const validator = new SupplyChainValidator({
      enabled: true,
      mode: 'block',
      project_root: tmpDir,
      blocked_packages: ['left-pad'],
      block_on_blocked_package: true,
      check_every_requests: 1,
    });

    const decision = validator.evaluate({
      effectiveMode: 'enforce',
    });
    expect(decision.checked).toBe(true);
    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'supply_chain_blocked_package_present')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });

  test('skips checks until configured request interval is reached', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-supply-chain-'));
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'tmp-project',
      version: '1.0.0',
      dependencies: {},
    });

    const validator = new SupplyChainValidator({
      enabled: true,
      mode: 'monitor',
      project_root: tmpDir,
      check_every_requests: 2,
    });

    const first = validator.evaluate({
      effectiveMode: 'monitor',
    });
    const second = validator.evaluate({
      effectiveMode: 'monitor',
    });

    expect(first.checked).toBe(false);
    expect(second.checked).toBe(true);
  });

  test('detects lockfile drift between baseline and current state', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-supply-chain-'));
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'tmp-project',
      version: '1.0.0',
      dependencies: {},
    });
    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), '{"lockfileVersion":3,"packages":{}}', 'utf8');

    const validator = new SupplyChainValidator({
      enabled: true,
      mode: 'block',
      project_root: tmpDir,
      block_on_lockfile_drift: true,
      check_every_requests: 1,
    });

    fs.writeFileSync(
      path.join(tmpDir, 'package-lock.json'),
      '{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}',
      'utf8'
    );

    const decision = validator.evaluate({
      effectiveMode: 'enforce',
    });

    expect(decision.checked).toBe(true);
    expect(decision.detected).toBe(true);
    expect(decision.findings.some((item) => item.code === 'supply_chain_lockfile_drift')).toBe(true);
    expect(decision.shouldBlock).toBe(true);
  });
});

