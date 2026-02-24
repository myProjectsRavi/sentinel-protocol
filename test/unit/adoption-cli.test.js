const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  detectFramework,
  normalizeFramework,
  normalizeProviders,
  injectProviderTargets,
  frameworkSnippet,
  appendGeneratedHints,
} = require('../../src/cli/adoption');

function makeProjectWithDeps(dependencies = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-adoption-cli-'));
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    `${JSON.stringify({ name: 'tmp', version: '1.0.0', dependencies }, null, 2)}\n`,
    'utf8'
  );
  return dir;
}

describe('adoption CLI helpers', () => {
  test('detectFramework identifies supported frameworks without false positives', () => {
    const expressDir = makeProjectWithDeps({ express: '^4.0.0' });
    const fastifyDir = makeProjectWithDeps({ fastify: '^4.0.0' });
    const nextDir = makeProjectWithDeps({ next: '^15.0.0' });
    const koaDir = makeProjectWithDeps({ koa: '^2.0.0' });
    const honoDir = makeProjectWithDeps({ hono: '^4.0.0' });
    const nestDir = makeProjectWithDeps({ '@nestjs/core': '^10.0.0' });
    const noneDir = makeProjectWithDeps({});

    expect(detectFramework(expressDir)).toBe('express');
    expect(detectFramework(fastifyDir)).toBe('fastify');
    expect(detectFramework(nextDir)).toBe('nextjs');
    expect(detectFramework(koaDir)).toBe('koa');
    expect(detectFramework(honoDir)).toBe('hono');
    expect(detectFramework(nestDir)).toBe('nestjs');
    expect(detectFramework(noneDir)).toBeNull();
  });

  test('normalizeFramework supports aliases and rejects unknown values', () => {
    expect(normalizeFramework('next')).toBe('nextjs');
    expect(normalizeFramework('NEXTJS')).toBe('nextjs');
    expect(normalizeFramework('express')).toBe('express');
    expect(normalizeFramework('unknown')).toBeNull();
  });

  test('normalizeProviders keeps only supported providers and defaults to openai', () => {
    expect(normalizeProviders('openai,anthropic,google,ollama')).toEqual([
      'openai',
      'anthropic',
      'google',
      'ollama',
    ]);
    expect(normalizeProviders('openai,openai,foo')).toEqual(['openai']);
    expect(normalizeProviders('')).toEqual(['openai']);
  });

  test('injectProviderTargets writes resilience mesh targets for selected providers', () => {
    const config = injectProviderTargets({ runtime: { upstream: {} } }, ['openai', 'ollama']);
    expect(config.runtime.upstream.resilience_mesh.targets.openai.provider).toBe('openai');
    expect(config.runtime.upstream.resilience_mesh.targets.openai.contract).toBe('openai_chat_v1');
    expect(config.runtime.upstream.resilience_mesh.targets.ollama.provider).toBe('ollama');
    expect(config.runtime.upstream.resilience_mesh.targets.ollama.contract).toBe('ollama_chat_v1');
  });

  test('frameworkSnippet always includes proxy base URL guidance', () => {
    const snippet = frameworkSnippet('express');
    expect(snippet.includes('# Express proxy mode')).toBe(true);
    expect(snippet.includes("baseURL: 'http://127.0.0.1:8787/v1'")).toBe(true);
    expect(snippet.includes("'x-sentinel-target': 'openai'")).toBe(true);
    expect(snippet.includes("const { createSentinel } = require('sentinel-protocol');")).toBe(true);
  });

  test('frameworkSnippet is generated for each supported framework', () => {
    const frameworks = ['express', 'fastify', 'nextjs', 'koa', 'hono', 'nestjs'];
    for (const framework of frameworks) {
      const snippet = frameworkSnippet(framework);
      expect(snippet.includes('# Optional embed mode')).toBe(true);
      expect(snippet.includes("const sentinel = createSentinel(config);")).toBe(true);
    }
  });

  test('appendGeneratedHints appends deterministic hint block', () => {
    const file = path.join(os.tmpdir(), `sentinel-init-hints-${Date.now()}.yaml`);
    fs.writeFileSync(file, 'version: 1\nmode: monitor\n', 'utf8');
    appendGeneratedHints(file, {
      framework: 'fastify',
      providers: ['openai', 'anthropic'],
    });
    const content = fs.readFileSync(file, 'utf8');
    expect(content.includes('# --- Sentinel Init Hints (generated) ---')).toBe(true);
    expect(content.includes('# Providers selected: openai, anthropic')).toBe(true);
    expect(content.includes('# Framework detected: fastify')).toBe(true);
    expect(content.includes('SENTINEL_OPENAI_API_KEY')).toBe(true);
  });
});
