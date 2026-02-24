const fs = require('fs');
const path = require('path');

const PROVIDER_ORDER = Object.freeze(['openai', 'anthropic', 'google', 'ollama']);
const FRAMEWORKS = Object.freeze(['express', 'fastify', 'nextjs', 'koa', 'hono', 'nestjs', 'none']);
const HINT_BLOCK_START = '# --- Sentinel Init Hints (generated) ---';
const HINT_BLOCK_END = '# --- End Sentinel Init Hints ---';

const FRAMEWORK_LABELS = Object.freeze({
  express: 'Express',
  fastify: 'Fastify',
  nextjs: 'Next.js',
  koa: 'Koa',
  hono: 'Hono',
  nestjs: 'NestJS',
  none: 'Generic Node.js',
});

function normalizeFramework(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized) {
    return null;
  }
  if (normalized === 'next') {
    return 'nextjs';
  }
  if (FRAMEWORKS.includes(normalized)) {
    return normalized;
  }
  return null;
}

function readPackageDependencies(projectRoot) {
  const packageJsonPath = path.join(projectRoot, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    return null;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    return {
      ...(parsed.dependencies || {}),
      ...(parsed.devDependencies || {}),
    };
  } catch {
    return null;
  }
}

function detectFramework(projectRoot = process.cwd()) {
  const deps = readPackageDependencies(projectRoot);
  if (!deps) {
    return null;
  }
  const has = (name) => Object.prototype.hasOwnProperty.call(deps, name);
  if (has('@nestjs/core') || has('@nestjs/common') || has('@nestjs/platform-express') || has('@nestjs/platform-fastify')) {
    return 'nestjs';
  }
  if (has('next')) {
    return 'nextjs';
  }
  if (has('fastify')) {
    return 'fastify';
  }
  if (has('koa')) {
    return 'koa';
  }
  if (has('@hono/node-server') || has('hono')) {
    return 'hono';
  }
  if (has('express')) {
    return 'express';
  }
  return null;
}

function normalizeProviders(input) {
  const raw = Array.isArray(input) ? input : String(input || '').split(',');
  const seen = new Set();
  const out = [];
  for (const value of raw) {
    const provider = String(value || '').trim().toLowerCase();
    if (!provider || !PROVIDER_ORDER.includes(provider) || seen.has(provider)) {
      continue;
    }
    seen.add(provider);
    out.push(provider);
  }
  if (out.length > 0) {
    return out;
  }
  return ['openai'];
}

function providerContract(provider) {
  if (provider === 'anthropic') {
    return 'anthropic_messages_v1';
  }
  if (provider === 'google') {
    return 'google_generative_v1';
  }
  if (provider === 'ollama') {
    return 'ollama_chat_v1';
  }
  return 'openai_chat_v1';
}

function providerBaseUrl(provider) {
  if (provider === 'anthropic') {
    return 'https://api.anthropic.com';
  }
  if (provider === 'google') {
    return 'https://generativelanguage.googleapis.com';
  }
  if (provider === 'ollama') {
    return 'http://127.0.0.1:11434';
  }
  return 'https://api.openai.com';
}

function proxySdkSnippet(provider = 'openai') {
  const target = PROVIDER_ORDER.includes(provider) ? provider : 'openai';
  return [
    "import OpenAI from 'openai';",
    '',
    'const client = new OpenAI({',
    "  apiKey: process.env.OPENAI_API_KEY || 'sk-sentinel-local',",
    "  baseURL: 'http://127.0.0.1:8787/v1',",
    `  defaultHeaders: { 'x-sentinel-target': '${target}' },`,
    '});',
  ].join('\n');
}

function embedSdkSnippet() {
  return [
    "const { createSentinel } = require('sentinel-protocol');",
    'const sentinel = createSentinel(config);',
    'app.use(sentinel.middleware());',
    'sentinel.start();',
  ].join('\n');
}

function injectProviderTargets(config, providers) {
  const normalizedProviders = normalizeProviders(providers);
  const next = JSON.parse(JSON.stringify(config || {}));
  next.runtime = next.runtime && typeof next.runtime === 'object' ? next.runtime : {};
  next.runtime.upstream = next.runtime.upstream && typeof next.runtime.upstream === 'object' ? next.runtime.upstream : {};
  const mesh = next.runtime.upstream.resilience_mesh && typeof next.runtime.upstream.resilience_mesh === 'object'
    ? next.runtime.upstream.resilience_mesh
    : {};
  mesh.targets = mesh.targets && typeof mesh.targets === 'object' && !Array.isArray(mesh.targets)
    ? mesh.targets
    : {};

  for (const provider of normalizedProviders) {
    mesh.targets[provider] = {
      enabled: true,
      provider,
      contract: providerContract(provider),
      base_url: providerBaseUrl(provider),
      headers: {},
    };
  }

  next.runtime.upstream.resilience_mesh = mesh;
  return next;
}

function frameworkSnippet(framework) {
  const normalized = normalizeFramework(framework) || 'none';
  const label = FRAMEWORK_LABELS[normalized] || 'Framework';
  return [
    `# ${label} proxy mode (zero app-code patching):`,
    proxySdkSnippet('openai'),
    '',
    '# Optional embed mode (connect-compatible middleware):',
    embedSdkSnippet(),
  ].join('\n');
}

function providerEnvHints(providers) {
  const normalizedProviders = normalizeProviders(providers);
  const lines = [];
  lines.push('# Export provider credentials before sentinel start:');
  if (normalizedProviders.includes('openai')) {
    lines.push('#   export SENTINEL_OPENAI_API_KEY=...');
  }
  if (normalizedProviders.includes('anthropic')) {
    lines.push('#   export SENTINEL_ANTHROPIC_API_KEY=...');
  }
  if (normalizedProviders.includes('google')) {
    lines.push('#   export SENTINEL_GOOGLE_API_KEY=...');
  }
  if (normalizedProviders.includes('ollama')) {
    lines.push('#   # Optional override for local Ollama endpoint:');
    lines.push('#   export SENTINEL_OLLAMA_URL=http://127.0.0.1:11434');
  }
  return lines;
}

function appendGeneratedHints(configPath, options = {}) {
  const framework = normalizeFramework(options.framework) || 'none';
  const providers = normalizeProviders(options.providers || ['openai']);
  const snippet = frameworkSnippet(framework).split('\n').map((line) => `#   ${line}`);

  const hintLines = [
    '# This block is regenerated by `sentinel init` when profile/provider/framework options change.',
    `# Providers selected: ${providers.join(', ')}`,
    ...providerEnvHints(providers),
    '# Route request traffic with header:',
    `#   x-sentinel-target: ${providers[0]}`,
    `# Framework detected: ${framework}`,
    '# Quick-start snippet:',
    ...snippet,
  ];

  const current = fs.readFileSync(configPath, 'utf8');
  const startIdx = current.indexOf(HINT_BLOCK_START);
  const stripped = startIdx >= 0 ? current.slice(0, startIdx).trimEnd() : current.trimEnd();
  const block = [HINT_BLOCK_START, ...hintLines, HINT_BLOCK_END].join('\n');
  fs.writeFileSync(configPath, `${stripped}\n\n${block}\n`, 'utf8');
}

async function detectOllamaAvailable(options = {}) {
  const timeoutMs = Number.isFinite(Number(options.timeoutMs)) ? Number(options.timeoutMs) : 500;
  const url = String(options.url || 'http://127.0.0.1:11434/api/tags');
  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: AbortSignal.timeout(timeoutMs),
    });
    return response.ok;
  } catch {
    return false;
  }
}

module.exports = {
  PROVIDER_ORDER,
  FRAMEWORKS,
  FRAMEWORK_LABELS,
  normalizeFramework,
  detectFramework,
  normalizeProviders,
  injectProviderTargets,
  proxySdkSnippet,
  embedSdkSnippet,
  frameworkSnippet,
  appendGeneratedHints,
  detectOllamaAvailable,
};
