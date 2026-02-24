const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  clampPositiveInt,
  normalizeMode,
} = require('../utils/primitives');

function sha256File(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function toArray(value) {
  return Array.isArray(value) ? value : [];
}

function loadJson(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

class SupplyChainValidator {
  constructor(config = {}) {
    this.enabled = config.enabled === true;
    this.mode = normalizeMode(config.mode, 'monitor', ['monitor', 'block']);
    this.projectRoot = String(config.project_root || process.cwd());
    this.maxModuleEntries = clampPositiveInt(config.max_module_entries, 10000, 64, 1_000_000);
    this.checkEveryRequests = clampPositiveInt(config.check_every_requests, 100, 1, 1000000);
    this.blockOnLockfileDrift = config.block_on_lockfile_drift === true;
    this.blockOnBlockedPackage = config.block_on_blocked_package === true;
    this.requireLockfile = config.require_lockfile === true;
    this.observability = config.observability !== false;
    this.blockedPackages = toArray(config.blocked_packages)
      .map((item) => String(item || '').trim().toLowerCase())
      .filter(Boolean)
      .slice(0, 2048);
    this.lockFiles = toArray(config.lock_files).length > 0
      ? toArray(config.lock_files)
        .map((item) => String(item || '').trim())
        .filter(Boolean)
        .slice(0, 16)
      : ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

    this.requestCounter = 0;
    this.baseline = this.captureBaseline();
  }

  isEnabled() {
    return this.enabled === true;
  }

  resolvePath(relativePath) {
    return path.isAbsolute(relativePath)
      ? relativePath
      : path.join(this.projectRoot, relativePath);
  }

  captureBaseline() {
    const lockDigests = {};
    for (const fileName of this.lockFiles) {
      const absolute = this.resolvePath(fileName);
      if (!fs.existsSync(absolute)) {
        continue;
      }
      try {
        lockDigests[fileName] = sha256File(absolute);
      } catch {
        lockDigests[fileName] = '';
      }
    }
    const moduleLoadDigest = crypto
      .createHash('sha256')
      .update(JSON.stringify(process.moduleLoadList.slice(0, this.maxModuleEntries)))
      .digest('hex');
    return {
      lock_digests: lockDigests,
      module_load_digest: moduleLoadDigest,
      captured_at: new Date().toISOString(),
    };
  }

  evaluate({ effectiveMode = 'monitor', force = false } = {}) {
    if (!this.isEnabled()) {
      return {
        enabled: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    this.requestCounter += 1;
    if (!force && this.requestCounter % this.checkEveryRequests !== 0) {
      return {
        enabled: true,
        mode: this.mode,
        checked: false,
        detected: false,
        shouldBlock: false,
        reason: 'clean',
        findings: [],
      };
    }

    const findings = [];
    const current = this.captureBaseline();
    const baselineLockKeys = new Set(Object.keys(this.baseline.lock_digests || {}));
    const currentLockKeys = new Set(Object.keys(current.lock_digests || {}));

    if (this.requireLockfile && currentLockKeys.size === 0) {
      findings.push({
        code: 'supply_chain_lockfile_missing',
        blockEligible: this.blockOnLockfileDrift,
      });
    }

    for (const key of baselineLockKeys) {
      const previous = this.baseline.lock_digests[key];
      const currentDigest = current.lock_digests[key];
      if (previous && currentDigest && previous !== currentDigest) {
        findings.push({
          code: 'supply_chain_lockfile_drift',
          lock_file: key,
          blockEligible: this.blockOnLockfileDrift,
        });
      }
    }
    for (const key of currentLockKeys) {
      if (!baselineLockKeys.has(key)) {
        findings.push({
          code: 'supply_chain_new_lockfile_detected',
          lock_file: key,
          blockEligible: false,
        });
      }
    }

    const packageJson = loadJson(this.resolvePath('package.json'));
    if (packageJson && packageJson.dependencies && typeof packageJson.dependencies === 'object') {
      for (const packageName of Object.keys(packageJson.dependencies)) {
        if (!this.blockedPackages.includes(String(packageName || '').toLowerCase())) {
          continue;
        }
        findings.push({
          code: 'supply_chain_blocked_package_present',
          package: packageName,
          blockEligible: this.blockOnBlockedPackage,
        });
      }
    }

    if (this.baseline.module_load_digest && current.module_load_digest !== this.baseline.module_load_digest) {
      findings.push({
        code: 'supply_chain_module_load_drift',
        blockEligible: false,
      });
    }

    const detected = findings.length > 0;
    const shouldBlock =
      detected &&
      this.mode === 'block' &&
      String(effectiveMode || '').toLowerCase() === 'enforce' &&
      findings.some((finding) => finding.blockEligible === true);

    return {
      enabled: true,
      mode: this.mode,
      checked: true,
      detected,
      shouldBlock,
      reason: detected ? String(findings[0].code || 'supply_chain_violation') : 'clean',
      findings,
      baseline_captured_at: this.baseline.captured_at,
      lock_files_observed: Object.keys(current.lock_digests || {}),
    };
  }
}

module.exports = {
  SupplyChainValidator,
};
