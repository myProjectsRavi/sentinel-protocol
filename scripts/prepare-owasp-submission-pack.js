#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ARTIFACTS = [
  'README.md',
  'CHANGELOG.md',
  'docs/OWASP_LLM_TOP10_SENTINEL_MAP.md',
  'docs/OWASP-HARDENING.md',
  'docs/openapi.yaml',
  'docs/benchmarks/METHODOLOGY.md',
  'docs/benchmarks/COMPETITOR_COMPARISON.md',
  'docs/benchmarks/results/standard-datasets.json',
  'docs/SECURITY_RELIABILITY_EVIDENCE_V4_PHASEA.md',
  'docs/evidence/WIZARD_VALIDATION.md',
  'docs/evidence/FRAMEWORK_DETECT_MATRIX.md',
  'docs/evidence/GITHUB_ACTION_DEMO.md'
];

const OUT_PATH = path.resolve(__dirname, '..', 'docs', 'owasp', 'submission-manifest.json');

function sha256File(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function buildManifest() {
  const root = path.resolve(__dirname, '..');
  const files = ARTIFACTS.map((relativePath) => {
    const absolute = path.resolve(root, relativePath);
    if (!fs.existsSync(absolute)) {
      throw new Error(`missing_artifact:${relativePath}`);
    }
    const stat = fs.statSync(absolute);
    return {
      path: relativePath,
      size_bytes: stat.size,
      sha256: sha256File(absolute),
    };
  });

  return {
    generated_at: new Date().toISOString(),
    pack: 'owasp_reference_submission',
    project: 'sentinel-protocol',
    version: '1.0.0',
    claim_boundary: 'Only reproducible in-repo evidence is claimed. Unknown/unmeasured values are marked explicitly.',
    artifacts: files,
  };
}

function main() {
  const manifest = buildManifest();
  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  console.log(`Wrote ${OUT_PATH}`);
  console.log(`artifacts=${manifest.artifacts.length}`);
}

main();
