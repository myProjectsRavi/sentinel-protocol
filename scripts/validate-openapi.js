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

const allowedMethods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']);
const operationIds = new Set();
for (const [routePath, routeDef] of Object.entries(spec.paths)) {
  if (!routePath.startsWith('/')) {
    fail(`OpenAPI path must start with '/': ${routePath}`);
  }
  if (!routeDef || typeof routeDef !== 'object') {
    fail(`OpenAPI path must define an object: ${routePath}`);
  }
  for (const [method, operation] of Object.entries(routeDef)) {
    const loweredMethod = String(method).toLowerCase();
    if (!allowedMethods.has(loweredMethod)) {
      continue;
    }
    if (!operation || typeof operation !== 'object') {
      fail(`OpenAPI operation must be an object: ${routePath} ${loweredMethod}`);
    }
    if (!operation.operationId || typeof operation.operationId !== 'string') {
      fail(`OpenAPI operationId missing: ${routePath} ${loweredMethod}`);
    }
    if (operationIds.has(operation.operationId)) {
      fail(`OpenAPI operationId must be unique: ${operation.operationId}`);
    }
    operationIds.add(operation.operationId);

    if (!operation.responses || typeof operation.responses !== 'object' || Object.keys(operation.responses).length === 0) {
      fail(`OpenAPI responses missing: ${routePath} ${loweredMethod}`);
    }
    for (const [status, response] of Object.entries(operation.responses)) {
      if (!/^(default|[1-5][0-9][0-9]|[1-5]XX)$/.test(String(status))) {
        fail(`OpenAPI response status must be HTTP code/default: ${routePath} ${loweredMethod} -> ${status}`);
      }
      if (!response || typeof response !== 'object' || typeof response.description !== 'string' || !response.description.trim()) {
        fail(`OpenAPI response description missing: ${routePath} ${loweredMethod} -> ${status}`);
      }
    }
  }
}

console.log(`OpenAPI spec valid: ${specPath}`);
