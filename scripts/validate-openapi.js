#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const specPath = path.join(__dirname, '..', 'docs', 'openapi.yaml');

function fail(message) {
  console.error(message);
  process.exit(1);
}

if (!fs.existsSync(specPath)) {
  fail(`OpenAPI spec not found: ${specPath}`);
}

let spec;
try {
  spec = yaml.load(fs.readFileSync(specPath, 'utf8'));
} catch (error) {
  fail(`OpenAPI parse failed: ${error.message}`);
}

if (!spec || typeof spec !== 'object') {
  fail('OpenAPI spec must be an object');
}
if (!String(spec.openapi || '').startsWith('3.')) {
  fail('OpenAPI version must be 3.x');
}
if (!spec.info || typeof spec.info !== 'object') {
  fail('OpenAPI spec must include info');
}
if (!spec.paths || typeof spec.paths !== 'object') {
  fail('OpenAPI spec must include paths');
}

console.log(`OpenAPI spec valid: ${specPath}`);
